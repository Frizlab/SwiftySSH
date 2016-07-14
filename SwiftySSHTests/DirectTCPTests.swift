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
    
    //ncat -lkv --chat 127.0.0.1 12345
    func testForwarding() {
        let expectation = self.expectation(withDescription: "testForwarding")
        
        let testString = "test 😀"
        
        let manager = Manager("vagrant", host:"127.0.0.1", port: 2222)
            .session{(session) in
                session.authenticate(.password(password: "vagrant"))
        }
        .connect()
            
            
        let tunnel = manager.directTCP("127.0.0.1", remotePort: 12345)

        tunnel.onClose({ (error) -> Void in
            XCTAssert(error == nil)
        })
        .onRead { (_, data, error) -> Void in
            XCTAssert(error == nil)
            
            XCTAssertFalse(data == nil)
            
            if let data = data {
                let s = NSString(bytes: data, length: data.count, encoding: String.Encoding.utf8.rawValue)
                print(s)
                expectation.fulfill()
            }
        }
        .onOpen{ (channel, error) -> Void in
            XCTAssert(error == nil)
            channel.write(testString, handler: { (error) -> Void in
                XCTAssert(error == nil)
            })
        }
        .open()
        
        
        waitForExpectations(withTimeout: 3, handler: nil)
    }    
}
