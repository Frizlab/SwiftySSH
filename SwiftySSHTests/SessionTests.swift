//
//  SwiftySSHTests.swift
//  SwiftySSHTests
//
//  Created by Vladimir Solomenchuk on 10/23/14.
//  Copyright (c) 2014 Vladimir Solomenchuk. All rights reserved.
//

import Cocoa
import XCTest
@testable import SwiftySSH

class SwiftySSHTests: XCTestCase {

    func testValidPassword() {
        let expectation = expectationWithDescription("testValidPassword")
        
        let session = Session("vovasty", host:"127.0.0.1", port: 2222)
        .onDisconnect { (session, error) -> Void in
            XCTAssert(error == nil, "\(error)")
        }
        .authenticate(.Password(password: "3Dk@hmPC"))
        .onConnect({ (session, error) -> Void in
            XCTAssert(error == nil, "\(error)")
            expectation.fulfill()
        })
        .connect()
        
        waitForExpectationsWithTimeout(100, handler: nil)

        session.disconnect()
    }

    func testInvalidPassword() {
        let expectation = expectationWithDescription("testInvalidPassword")
        let session = Session("vovasty", host:"127.0.0.1", port: 2222)
            .onDisconnect { (session, error) -> Void in
                XCTAssert(error == nil, "\(error)")
            }
            .authenticate(.Password(password: "wrong password"))
            .onConnect({ (session, error) -> Void in
                XCTAssertFalse(error == nil, "\(error)")
                expectation.fulfill()
            })
            .connect()
        
        waitForExpectationsWithTimeout(1000, handler: nil)
        
        session.disconnect()
    }

    func testPublicKey() {
        let expectation = expectationWithDescription("testPublicKey")
        let session = Session("vovasty", host:"solomav.no-ip.org", port: 9999)
            .onDisconnect { (session, error) -> Void in
                XCTAssert(error == nil, "\(error)")
            }
            .authenticate(.PublicKey(publicKeyPath: "/Users/i843418/.ssh/default.pub", privateKeyPath: "/Users/i843418/.ssh/default", passphrase: "V5o!0m3n"))
            .onConnect({ (session, error) -> Void in
                XCTAssert(error == nil, "\(error)")
                expectation.fulfill()
            })
            .connect()
        
        waitForExpectationsWithTimeout(1000, handler: nil)
        
        session.disconnect()
    }

    
    
    func testConnectByURL() {
        let expectation = expectationWithDescription("testConnectByURL")
        
        let session = Session("ssh://vovasty@127.0.0.1:2222")
        XCTAssertNotNil(session)
        
        session!.onDisconnect { (session, error) -> Void in
                XCTAssert(error == nil, "\(error)")
        }
        .authenticate(.Password(password: "3Dk@hmPC"))
        .onConnect({ (session, error) -> Void in
            XCTAssert(error == nil, "\(error)")
            expectation.fulfill()
        })
        .connect()
        
        waitForExpectationsWithTimeout(3, handler: nil)
        
        session!.disconnect()
    }
}
