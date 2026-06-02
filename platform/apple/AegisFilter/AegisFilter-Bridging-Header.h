//
//  AegisFilter-Bridging-Header.h
//
//  Objective-C bridging header for the AegisFilter Network Extension target.
//  Imports the C ABI of the Rust static library (aegis-apple-ffi) so Swift can
//  call aegis_apple_engine_new() / aegis_apple_classify_text() / _free().
//
//  In Xcode, set:
//    Build Settings → Swift Compiler - General → Objective-C Bridging Header
//      = platform/apple/AegisFilter/AegisFilter-Bridging-Header.h
//    Build Settings → Header Search Paths
//      += $(SRCROOT)/../aegis-apple-ffi/include  (where aegis_apple.h lives)
//

#import "aegis_apple.h"
