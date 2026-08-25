package com.fortress.ui

import android.app.Activity
import android.app.Dialog
import android.graphics.Color
import android.graphics.Typeface
import android.os.Handler
import android.os.Looper
import android.util.Log
import android.util.TypedValue
import android.view.Gravity
import android.view.WindowManager
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import com.facebook.react.bridge.ReactApplicationContext
import com.fortress.root.ThreatResult

/**
 * Full-screen, non-dismissible overlay for [onCriticalThreat] = `block_ui`.
 * Does not rely on JavaScript. Dismiss is intentionally not supported in M1.
 */
object UiBlocker {
  private const val TAG = "FortressUiBlocker"

  @Volatile
  private var showing = false

  private val mainHandler = Handler(Looper.getMainLooper())

  fun show(
    reactContext: ReactApplicationContext,
    threats: List<ThreatResult>,
  ) {
    val summary =
      threats
        .filter { it.severity == "high" || it.severity == "critical" }
        .joinToString("\n") { "• ${it.type}: ${it.message}" }
        .ifEmpty { "A high or critical security threat was detected." }

    show(reactContext, summary, force = false)
  }

  fun show(
    reactContext: ReactApplicationContext,
    message: String,
    force: Boolean = false,
  ) {
    if (showing && !force) {
      Log.i(TAG, "block_ui already visible — skip")
      return
    }

    fun tryShow(attempt: Int) {
      val activity = reactContext.currentActivity
      if (activity == null || activity.isFinishing) {
        if (attempt < 10) {
          mainHandler.postDelayed({ tryShow(attempt + 1) }, 200)
        } else {
          Log.w(TAG, "No current activity after retries — cannot show block_ui")
        }
        return
      }

      activity.runOnUiThread {
        showOnActivity(activity, message, force)
      }
    }

    mainHandler.post { tryShow(0) }
  }

  private fun showOnActivity(
    activity: Activity,
    summary: String,
    force: Boolean,
  ) {
    if (showing && !force) {
      return
    }
    if (activity.isFinishing) {
      return
    }

    showing = true

    try {
      val density = activity.resources.displayMetrics.density
      val padding = (24 * density).toInt()

      val title =
        TextView(activity).apply {
          text = "Security threat detected"
          setTextColor(Color.WHITE)
          setTextSize(TypedValue.COMPLEX_UNIT_SP, 22f)
          typeface = Typeface.DEFAULT_BOLD
          gravity = Gravity.CENTER_HORIZONTAL
        }

      val body =
        TextView(activity).apply {
          text =
            "This app has been blocked because the device appears compromised.\n\n$summary"
          setTextColor(Color.parseColor("#E2E8F0"))
          setTextSize(TypedValue.COMPLEX_UNIT_SP, 15f)
          setPadding(0, padding, 0, 0)
        }

      val footer =
        TextView(activity).apply {
          text = "Contact support if you believe this is an error.\n(Force-quit the app to dismiss while testing.)"
          setTextColor(Color.parseColor("#94A3B8"))
          setTextSize(TypedValue.COMPLEX_UNIT_SP, 13f)
          setPadding(0, padding, 0, 0)
          gravity = Gravity.CENTER_HORIZONTAL
        }

      val content =
        LinearLayout(activity).apply {
          orientation = LinearLayout.VERTICAL
          setBackgroundColor(Color.parseColor("#0F172A"))
          setPadding(padding, padding * 2, padding, padding)
          addView(title)
          addView(body)
          addView(footer)
        }

      val scroll =
        ScrollView(activity).apply {
          setBackgroundColor(Color.parseColor("#0F172A"))
          isFillViewport = true
          addView(
            content,
            LinearLayout.LayoutParams(
              LinearLayout.LayoutParams.MATCH_PARENT,
              LinearLayout.LayoutParams.WRAP_CONTENT,
            ),
          )
        }

      val dialog =
        Dialog(activity, android.R.style.Theme_Black_NoTitleBar_Fullscreen).apply {
          setCancelable(false)
          setCanceledOnTouchOutside(false)
          setContentView(scroll)
          setOnKeyListener { _, _, _ -> true }
        }

      dialog.window?.apply {
        addFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON)
        setLayout(
          WindowManager.LayoutParams.MATCH_PARENT,
          WindowManager.LayoutParams.MATCH_PARENT,
        )
      }
      dialog.show()
      Log.e(TAG, "block_ui overlay shown")
    } catch (error: Exception) {
      showing = false
      Log.e(TAG, "Failed to show block_ui overlay: ${error.message}", error)
    }
  }
}
