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
            
            func sshSession(_ session: Session, validateFingerprint fingerprint: Fingerprint, handler: FingerprintDecisionHandler) {
                handler(true)
            }
            
            func sshSession(_ session: Session, authenticate methods: [AuthenticationMethods], handler: AuthenticationDecisionHandler) {
                handler(.password("vagrant"))
            }
            
            func sshSessionConnected(_ session: Session) {
                expectation.fulfill()
            }
            
            func sshSessionDisconnected(_ session: Session, error: Error?) {
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
            
            func sshSession(_ session: Session, validateFingerprint fingerprint: Fingerprint, handler: FingerprintDecisionHandler) {
                handler(true)
            }
            
            func sshSession(_ session: Session, authenticate methods: [AuthenticationMethods], handler: AuthenticationDecisionHandler) {
                handler(.password("vagrant1"))
            }
            
            func sshSessionConnected(_ session: Session) {
                
            }
            
            func sshSessionDisconnected(_ session: Session, error: Error?) {
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
