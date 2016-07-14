//
//  Funky.swift
//  SwiftySSH
//
//  Created by Solomenchuk, Vlad on 8/13/15.
//  Copyright © 2015 Vladimir Solomenchuk. All rights reserved.
//

import Foundation


struct Logger {
    func debug(_ msg: String) {
        print("debug: \(msg)")
    }
    func error(_ msg: String) {
        print("error: \(msg)")
    }
    func info(_ msg: String) {
        print("info: \(msg)")
    }
}

let logger = Logger()
