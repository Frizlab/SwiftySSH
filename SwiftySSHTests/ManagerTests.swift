//
//  DirectTCPTests.swift
//  SwiftySSH
//
//  Created by Solomenchuk, Vlad on 8/21/15.
//  Copyright © 2015 Vladimir Solomenchuk. All rights reserved.
//

import XCTest
@testable import SwiftySSH

class DirectTCPTests: XCTestCase {
    
    //python -m SimpleHTTPServer 12345
    func testRequest() {
        let expectation = self.expectation(description: "testRequest")
        
        let testString = "GET / HTTP/1.1\n\n"
        
        let data = testString.data(using: String.Encoding.utf8)!

        let manager = Manager(user: "vagrant", host:"127.0.0.1", port: 2222)
        manager.session
        .onValidate { (fingerptint, handler) in
            handler(allow: true)
        }
        .onAuthenticate { (methods, handler) in
            handler(authenticate: .password("vagrant"))
        }
        .connect()
        
        manager.request(port: 12345, send: data) { (data, error) in
            guard let data = data, error == nil else {
                XCTAssert(false)
                return
            }
            let s = String(data: data, encoding: String.Encoding.utf8)
            print(s)
            expectation.fulfill()
        }
        waitForExpectations(timeout: 3, handler: nil)
    }
    
    //ncat -lkv --chat 127.0.0.1 12346
    func testRead() {
        let writeExpectation = self.expectation(description: "write")
        let readExpectation = self.expectation(description: "read")
        
        let testString = "Hi guys 😀"
        
        let manager = Manager(user: "vagrant", host:"127.0.0.1", port: 2222)
        manager.session
            .onValidate { (fingerptint, handler) in
                handler(allow: true)
            }
            .onAuthenticate { (methods, handler) in
                handler(authenticate: .password("vagrant"))
        }
        .connect()
        
        let channel = manager.channel(port: 12346)
        channel.onOpen {
                channel.write(Array(testString.utf8)) { (error) in
                    guard error == nil else {
                        XCTAssert(false)
                        return
                    }
                    
                    writeExpectation.fulfill()
                }
            }
        .onRead { (data) in
            let s = String(bytes: data, encoding: String.Encoding.utf8)
            print(s)
            readExpectation.fulfill()
        }
        .onClose { (error) in
            XCTAssertNil(error)
        }
        .open()
        
        waitForExpectations(timeout: 3, handler: nil)
    }    

}
