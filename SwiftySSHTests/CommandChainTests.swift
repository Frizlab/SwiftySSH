//
//  CommandChainTests.swift
//  SwiftySSH
//
//  Created by Solomenchuk, Vlad on 8/21/15.
//  Copyright © 2015 Vladimir Solomenchuk. All rights reserved.
//

import XCTest
@testable import SwiftySSH

class CommandChainTests: XCTestCase {

    func testValue() {
        let mutant = CommandChain<String>()
        
        var result = "?"
        mutant.append { (arg) -> Void in
            result+="1"
        }
        
        XCTAssertEqual(result, "?")
        
        mutant.value = "?"
        
        XCTAssertEqual(result, "?1")
        
        mutant.append{ (value) -> Void in
            result += "2"
        }
        
        XCTAssertEqual(result, "?12")
    }
}
