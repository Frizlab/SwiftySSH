//
//  Utils.swift
//  SwiftySSH
//
//  Created by Solomenchuk, Vlad on 9/26/15.
//  Copyright © 2015 Vladimir Solomenchuk. All rights reserved.
//

import Foundation

func callSSH(session: Session, _ timeout: CFAbsoluteTime, @autoclosure _ f: ()->Int32) throws -> Int32 {
    
    let time = CFAbsoluteTimeGetCurrent() + timeout
    
    var rc = f()

    while rc == LIBSSH2_ERROR_EAGAIN {
        if (timeout > 0 && time < CFAbsoluteTimeGetCurrent()) {
            throw SSHError.Timeout
        }

        rc = f()
    }
    if rc != LIBSSH2_ERROR_NONE {
        if let error = session.sshError() {
            throw error
        }
        
        throw SSHError.Unknown(msg: "Unknown SSH error \(rc)")
    }
    
    return rc
}

func callSSHNotNull(session: Session, _ timeout: CFAbsoluteTime, @autoclosure _ f: ()->COpaquePointer) throws -> COpaquePointer {
    
    let time = CFAbsoluteTimeGetCurrent() + timeout
    
    var rc = f()
    
    while rc == nil {
        if  libssh2_session_last_error(session.session, nil, nil, 0) == LIBSSH2_ERROR_EAGAIN {
            if timeout > 0 && time < CFAbsoluteTimeGetCurrent() {
                throw SSHError.Timeout
            }
        }
        else {
            if let error = session.sshError() {
                throw error
            }
            
            throw SSHError.Unknown(msg: "Unknown SSH error \(rc)")
        }
        
        rc = f()
    }

    return rc
}