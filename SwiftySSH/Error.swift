//
//  SwiftyError.swift
//  SwiftySSH
//
//  Created by Vladimir Solomenchuk on 11/7/14.
//  Copyright (c) 2014 Vladimir Solomenchuk. All rights reserved.
//

import Foundation

public enum SSHError: ErrorType, CustomStringConvertible {
    case NotConnected
    case Timeout
    case InvalidFingerprint
    case Unknown(msg: String)
    case SSHError(code: Int32, msg: String)
    
    public var description: String {
        switch self {
        case NotConnected:
                return "Not connected"
        case Timeout:
            return "connection timeout"
        case InvalidFingerprint:
            return "Invalid fingerprint"
        case Unknown(let msg):
            return msg
        case SSHError(_, let msg):
            return msg
        }
    }
}
