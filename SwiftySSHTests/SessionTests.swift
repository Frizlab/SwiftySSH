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
        let expectation = self.expectation(description: "password")
        
        class Delegate: SessionDelegate {
            let expectation: XCTestExpectation
            
            init(_ expectation: XCTestExpectation) {
                self.expectation = expectation
            }
            
            func sshSession(session: Session, validateFingerprint fingerprint: Fingerprint, handler: FingerprintDecisionHandler) {
                handler(allow: true)
            }
            
            func sshSession(session: Session, authenticate methods: [AuthenticationMethods], handler: AuthenticationDecisionHandler) {
                handler(authenticate: .password("vagrant"))
            }
            
            func sshSessionConnected(session: Session) {
                expectation.fulfill()
            }
            
            func sshSessionDisconnected(session: Session, error: ErrorProtocol?) {
                XCTAssertNil(error)
            }
        }
        
        let delegate = Delegate(expectation)
        
        let session = Session(user: "vagrant", host:"127.0.0.1", port: 2222, keepaliveInterval: 10, maxErrorCounter: 3)
        session.delegate = delegate
        session.connect()
        
        waitForExpectations(timeout: 3, handler: nil)

        session.disconnect()
    }
    
    func testInValidPassword() {
        let expectation = self.expectation(description: "password")
        
        class Delegate: SessionDelegate {
            let expectation: XCTestExpectation
            
            init(_ expectation: XCTestExpectation) {
                self.expectation = expectation
            }
            
            func sshSession(session: Session, validateFingerprint fingerprint: Fingerprint, handler: FingerprintDecisionHandler) {
                handler(allow: true)
            }
            
            func sshSession(session: Session, authenticate methods: [AuthenticationMethods], handler: AuthenticationDecisionHandler) {
                handler(authenticate: .password("vagrant1"))
            }
            
            func sshSessionConnected(session: Session) {
                
            }
            
            func sshSessionDisconnected(session: Session, error: ErrorProtocol?) {
                XCTAssertNotNil(error)
                expectation.fulfill()
            }
        }
        
        let delegate = Delegate(expectation)
        
        let session = Session(user: "vagrant", host:"127.0.0.1", port: 2222, keepaliveInterval: 10, maxErrorCounter: 3)
        session.delegate = delegate
        session.connect()
        
        waitForExpectations(timeout: 3, handler: nil)
    }
}
