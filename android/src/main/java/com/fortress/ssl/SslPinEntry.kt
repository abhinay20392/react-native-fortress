package com.fortress.ssl

data class SslPinEntry(
  val host: String,
  val publicKeyHashes: List<String>,
  val includeSubdomains: Boolean,
)
