package com.fortress

import com.facebook.react.bridge.ReactApplicationContext

class FortressModule(reactContext: ReactApplicationContext) :
  NativeFortressSpec(reactContext) {

  override fun multiply(a: Double, b: Double): Double {
    return a * b
  }

  companion object {
    const val NAME = NativeFortressSpec.NAME
  }
}
