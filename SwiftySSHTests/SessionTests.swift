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
        let expectation = self.expectation(withDescription: "testValidPassword")
        
        let session = Session("vagrant", host:"127.0.0.1", port: 2222)
        .onDisconnect { (session, error) -> Void in
            XCTAssert(error == nil, "\(error)")
        }
        .authenticate(.password(password: "vagrant"))
        .onConnect({ (session, error) -> Void in
            XCTAssert(error == nil, "\(error)")
            expectation.fulfill()
        })
        .connect()
        
        waitForExpectations(withTimeout: 100, handler: nil)

        session.disconnect()
    }

    func testInvalidPassword() {
        let expectation = self.expectation(withDescription: "testInvalidPassword")
        let session = Session("vagrant", host:"127.0.0.1", port: 2222)
            .onDisconnect { (session, error) -> Void in
                XCTAssert(error == nil, "\(error)")
            }
            .authenticate(.password(password: "wrong password"))
            .onConnect({ (session, error) -> Void in
                XCTAssertFalse(error == nil, "\(error)")
                expectation.fulfill()
            })
            .connect()
        
        waitForExpectations(withTimeout: 1000, handler: nil)
        
        session.disconnect()
    }

    func testPublicKey() {
        let expectation = self.expectation(withDescription: "testPublicKey")
        let session = Session("vovasty", host:"127.0.0.1", port: 2222)
            .onDisconnect { (session, error) -> Void in
                XCTAssert(error == nil, "\(error)")
            }
            .authenticate(.publicKey(publicKeyPath: "/Users/i843418/.ssh/default.pub", privateKeyPath: "/Users/i843418/.ssh/default", passphrase: "V5o!0m3n"))
            .onConnect({ (session, error) -> Void in
                XCTAssert(error == nil, "\(error)")
                expectation.fulfill()
            })
            .connect()
        
        waitForExpectations(withTimeout: 1000, handler: nil)
        
        session.disconnect()
    }

    
    
    func testConnectByURL() {
        let expectation = self.expectation(withDescription: "testConnectByURL")
        
        let session = Session("ssh://vagrant@127.0.0.1:2222")
        XCTAssertNotNil(session)
        
        session!.onDisconnect { (session, error) -> Void in
                XCTAssert(error == nil, "\(error)")
        }
        .authenticate(.password(password: "vagrant"))
        .onConnect({ (session, error) -> Void in
            XCTAssert(error == nil, "\(error)")
            expectation.fulfill()
        })
        .connect()
        
        waitForExpectations(withTimeout: 3, handler: nil)
        
        session!.disconnect()
    }
}
