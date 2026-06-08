//
//  BulwarkFilter-Bridging-Header.h
//
//  Objective-C bridging header for the BulwarkFilter Network Extension target.
//  Imports the C ABI of the Rust static library (bulwark-apple-ffi) so Swift can
//  call bulwark_apple_engine_new() / bulwark_apple_classify_text() / _free().
//
//  In Xcode, set:
//    Build Settings → Swift Compiler - General → Objective-C Bridging Header
//      = platform/apple/BulwarkFilter/BulwarkFilter-Bridging-Header.h
//    Build Settings → Header Search Paths
//      += $(SRCROOT)/../bulwark-apple-ffi/include  (where bulwark_apple.h lives)
//

#import "bulwark_apple.h"
