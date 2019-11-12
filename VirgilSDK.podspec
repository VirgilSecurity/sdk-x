Pod::Spec.new do |s|
  s.name                        = "VirgilSDK"
  s.version                     = "7.0.3"
  s.swift_version               = "5.0"
  s.license                     = { :type => "BSD", :file => "LICENSE" }
  s.summary                     = "Virgil SDK for Apple devices and languages."
  s.homepage                    = "https://github.com/VirgilSecurity/virgil-sdk-x/"
  s.authors                     = { "Virgil Security" => "https://virgilsecurity.com/" }
  s.source                      = { :git => "https://github.com/VirgilSecurity/virgil-sdk-x.git", :tag => s.version }
  s.ios.deployment_target       = "9.0"
  s.osx.deployment_target       = "10.11"
  s.tvos.deployment_target      = "9.0"
  s.watchos.deployment_target   = "2.0"
  s.source_files                = 'Source/**/*.{h,m,swift}'
  s.public_header_files         = 'Source/VirgilSDK.h',
                                  'Source/KeychainStorage/*.h'
  s.osx.exclude_files           = "Source/**/iOS/*.swift"
  s.tvos.exclude_files          = "Source/**/iOS/*.swift"
  s.watchos.exclude_files       = "Source/**/iOS/*.swift"

  s.dependency "VirgilCrypto", "~> 5.2"
end
