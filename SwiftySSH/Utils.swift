//
//  Utils.swift
//  SwiftySSH
//
//  Created by Solomenchuk, Vlad on 9/26/15.
//  Copyright © 2015 Vladimir Solomenchuk. All rights reserved.
//

import Foundation

@discardableResult
func callSSH(_ session: Session, _ timeout: CFAbsoluteTime, _ f: @autoclosure () -> Int32) throws -> Int32 {
    
    let time = CFAbsoluteTimeGetCurrent() + timeout
    
    var rc = f()

    while rc == LIBSSH2_ERROR_EAGAIN {
        if (timeout > 0 && time < CFAbsoluteTimeGetCurrent()) {
            throw SSHError.timeout
        }

        rc = f()
    }
    if rc != LIBSSH2_ERROR_NONE {
        if let error = session.sshError() {
            throw error
        }
        
        throw SSHError.unknown(msg: "Unknown SSH error \(rc)")
    }
    
    return rc
}

@discardableResult
func callSSHNotNull(_ session: Session, _ timeout: CFAbsoluteTime, _ f: @autoclosure () -> OpaquePointer?) throws -> OpaquePointer? {
    
    let time = CFAbsoluteTimeGetCurrent() + timeout
    
    var rc = f()
    
    while rc == nil {
        if  libssh2_session_last_error(session.session, nil, nil, 0) == LIBSSH2_ERROR_EAGAIN {
            if timeout > 0 && time < CFAbsoluteTimeGetCurrent() {
                throw SSHError.timeout
            }
        }
        else {
            if let error = session.sshError() {
                throw error
            }
            
            throw SSHError.unknown(msg: "Unknown SSH error \(rc)")
        }
        
        rc = f()
    }

    return rc
}
