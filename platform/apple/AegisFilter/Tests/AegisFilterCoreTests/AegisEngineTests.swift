//
//  AegisEngineTests.swift — bridge tests (run on a Mac with the .a linked).
//
//  These mirror the Rust-side FFI tests across the Swift boundary. They require
//  the static library to be on the linker path; see README → "Run the Swift
//  bridge tests".
//

import XCTest
@testable import AegisFilterCore

final class AegisEngineTests: XCTestCase {

    func testEngineBuilds() {
        XCTAssertNotNil(AegisEngine())
    }

    func testBenignIsAllowed() throws {
        let engine = try XCTUnwrap(AegisEngine())
        let (action, category) = engine.classify("are you coming to football practice tonight?",
                                                  threadID: "t1")
        XCTAssertEqual(action, .allow)
        XCTAssertEqual(category, 1) // AEGIS_APPLE_CATEGORY_SAFE
    }

    func testImageRequestIsBlocked() throws {
        let engine = try XCTUnwrap(AegisEngine())
        let (action, category) = engine.classify("can you send me a pic of you",
                                                  threadID: "groomer")
        XCTAssertEqual(action, .block)
        XCTAssertEqual(category, 6) // AEGIS_APPLE_CATEGORY_CSAM_SUSPECTED
    }

    func testEmptyTextAllows() throws {
        let engine = try XCTUnwrap(AegisEngine())
        let (action, _) = engine.classify("", threadID: "")
        XCTAssertEqual(action, .allow)
    }
}
