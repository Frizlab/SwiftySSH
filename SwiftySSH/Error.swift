//
//  SwiftyError.swift
//  SwiftySSH
//
//  Created by Vladimir Solomenchuk on 11/7/14.
//  Copyright (c) 2014 Vladimir Solomenchuk. All rights reserved.
//

import Foundation

public enum SSHError: ErrorProtocol, CustomStringConvertible {
    case notConnected
    case timeout
    case invalidFingerprint
    case unknown(msg: String)
    case sshError(code: Int32, msg: String)
    
    public var description: String {
        switch self {
        case notConnected:
                return "Not connected"
        case timeout:
            return "connection timeout"
        case invalidFingerprint:
            return "Invalid fingerprint"
        case unknown(let msg):
            return msg
        case sshError(_, let msg):
            return msg
        }
    }
}
