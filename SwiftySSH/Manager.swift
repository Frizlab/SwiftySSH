//
//  Manager.swift
//  SwiftySSH
//
//  Created by Solomenchuk, Vlad on 7/31/15.
//  Copyright © 2015 Vladimir Solomenchuk. All rights reserved.
//

import Foundation

public class Manager {
    private let _session: Session
    
    init (_ user: String, host: String, port: UInt16) {
        _session = Session(user, host: host, port: port)
    }
    
    public func connect() -> Self{
        _session.connect()
        return self
    }
    
    public func session(_ closure: (Session)->Void) -> Self {
        closure(_session)
        return self
    }
    
    public func directTCP(_ remoteHost: String, remotePort: UInt16) -> Channel {
        return Channel(_session, remoteHost: remoteHost, remotePort: remotePort)
    }

}

