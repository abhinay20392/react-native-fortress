require "json"

package = JSON.parse(File.read(File.join(__dir__, "package.json")))

Pod::Spec.new do |s|
  s.name         = "Fortress"
  s.version      = package["version"]
  s.summary      = package["description"]
  s.homepage     = package["homepage"]
  s.license      = package["license"]
  s.authors      = package["author"]

  s.platforms    = { :ios => min_ios_version_supported }
  s.source       = { :git => "https://github.com/abhinay20392/react-native-fortress.git", :tag => "#{s.version}" }

  s.source_files = "ios/**/*.{h,m,mm,swift,cpp}", "cpp/*.{h,hpp,c,cpp}"
  s.private_header_files = "ios/**/*.h", "cpp/*.{h,hpp}"
  s.pod_target_xcconfig = {
    'HEADER_SEARCH_PATHS' => '"$(inherited)" "${PODS_TARGET_SRCROOT}/ios" "${PODS_TARGET_SRCROOT}/cpp"',
    'CLANG_CXX_LANGUAGE_STANDARD' => 'c++17',
  }

  install_modules_dependencies(s)
end
