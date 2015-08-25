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
    
    func testForwarding() {
        let expectation = expectationWithDescription("testForwarding")
        
        let manager = Manager("vovasty", host:"127.0.0.1", port: 2222)
            .session{(session) in
                session.authenticate(.Password(password: "3Dk@hmPC"))
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
                let s = NSString(bytes: data, length: data.count, encoding: NSUTF8StringEncoding)!
                print(s)
            }
        }
        .onOpen{ (channel, error) -> Void in
            XCTAssert(error == nil)
            channel.write("test 😀", handler: { (error) -> Void in
                XCTAssert(error == nil)
                expectation.fulfill()
            })
        }
        .open()
        
        
        waitForExpectationsWithTimeout(3, handler: nil)
    }    
}
