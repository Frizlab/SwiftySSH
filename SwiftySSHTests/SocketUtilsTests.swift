//
//  SocketUtilsTests.swift
//  SwiftySSH
//
//  Created by Solomenchuk, Vlad on 8/20/15.
//  Copyright © 2015 Vladimir Solomenchuk. All rights reserved.
//

import XCTest
@testable import SwiftySSH

class SocketUtilsTests: XCTestCase {
    
    func testNotResolve() {
        XCTAssertNil(resolveHost("adasd.asd.asd.as.dasdgoogle.com"))
    }
    
    func testResolve() {
        XCTAssertNotNil(resolveHost("google.com"))
    }

    
    func testSocket() {
        guard let addresses = resolveHost("google.com") else {
            XCTAssert(false)
            return
        }
        
        let socket = createSocket(addresses, port: 80, timeout: 1)
        XCTAssertNotNil(socket)
        
        defer {
            if socket != nil {
                CFSocketInvalidate(socket)
            }
        }
        
    }
    
    func testNotSocket() {
        guard let addresses = resolveHost("google.com") else {
            XCTAssert(false)
            return
        }
        
        let socket = createSocket(addresses, port: 33, timeout: 1)
        XCTAssertNil(socket)
        
        defer {
            if socket != nil {
                CFSocketInvalidate(socket)
            }
        }
        
    }

}
