//
//  Manager.swift
//  SwiftySSH
//
//  Created by Solomenchuk, Vlad on 7/31/15.
//  Copyright © 2015 Vladimir Solomenchuk. All rights reserved.
//

import Foundation

public class Manager {
    let session: ManagedSession

    init(user: String, host: String, port: UInt16, keepaliveInterval: Int = 10, maxErrorCounter: UInt = 3) {
        session = ManagedSession(user: user, host: host, port: port, keepaliveInterval: keepaliveInterval, maxErrorCounter: maxErrorCounter)
    }
    
    public func channel(host: String = "127.0.0.1", port: UInt16) -> ManagedChannel {
        return ManagedChannel(session: session, host: host, port: port)
    }
    
    deinit {
        session.disconnect()
    }
    
    public class ManagedChannel: Channel, SwiftySSH.ChannelDelegate {
        private var onOpenHandler: (() -> Void)?
        private var onClose: ((ErrorProtocol?) -> Void)?
        private var onRead: ((Array<UInt8>) -> Void)?
        
        required public init(session: Session, host: String, port: UInt16) {
            super.init(session: session, host: host, port: port)
            self.delegate = self
        }
        
        public func sshChannelOpened(channel: Channel) {
            onOpenHandler?()
        }
        
        public func sshChannelClosed(channel: Channel, error: ErrorProtocol?) {
            onClose?(error)
        }
        
        public func sshChannel(channel: Channel, received data: Array<UInt8>) {
            onRead?(data)
        }
        
        @discardableResult
        public func onOpen(handler: () -> Void) -> Self {
            onOpenHandler = handler
            return self
        }
        
        @discardableResult
        public func onClose(handler: (ErrorProtocol?) -> Void) -> Self {
            onClose = handler
            
            return self
        }
        
        @discardableResult
        public func onRead(handler: (Array<UInt8>) -> Void) -> Self {
            onRead = handler
            
            return self
        }
    }
    
    public class ManagedSession: Session, SwiftySSH.SessionDelegate {
        private var onValidateHandler: ((Fingerprint, FingerprintDecisionHandler) -> Void)?
        private var onDisconnectHandler: ((ErrorProtocol?) -> Void)?
        private var onConnectHandler: (() -> Void)?
        private var onAuthenticateHandler: (([AuthenticationMethods], AuthenticationDecisionHandler) -> Void)?

        
        required public init(user: String, host: String, port: UInt16, keepaliveInterval: Int, maxErrorCounter: UInt) {
            super.init(user: user, host: host, port: port, keepaliveInterval: keepaliveInterval, maxErrorCounter: maxErrorCounter)
            delegate = self
        }

        public func sshSession(session: Session, validateFingerprint fingerprint: Fingerprint, handler: FingerprintDecisionHandler) {
            onValidateHandler?(fingerprint, handler)
        }
        
        public func sshSession(session: Session, authenticate methods: [AuthenticationMethods], handler: AuthenticationDecisionHandler) {
            onAuthenticateHandler?(methods, handler)
        }
        
        public func sshSessionConnected(session: Session) {
            onConnectHandler?()
        }
        
        public func sshSessionDisconnected(session: Session, error: ErrorProtocol?) {
            
            onDisconnectHandler?(error)
        }
        
        @discardableResult
        public func onValidate(handler: (Fingerprint, FingerprintDecisionHandler) -> Void) -> Self {
            onValidateHandler = handler
            
            return self
        }
        
        @discardableResult
        public func onAuthenticate(handler: ([AuthenticationMethods], AuthenticationDecisionHandler) -> Void) -> Self {
            onAuthenticateHandler = handler
            
            return self
        }
        
        @discardableResult
        public func onConnect(handler: () -> Void) -> Self {
            onConnectHandler = handler
            
            return self
        }
        
        @discardableResult
        public func onDisconnect(handler: (ErrorProtocol?) -> Void) -> Self {
            onDisconnectHandler = handler
            
            return self
        }
    }
}

extension Manager {
    public func request(host: String = "127.0.0.1", port: UInt16, send data: Data, receive: (Data?, ErrorProtocol?) -> Void) {
        
        var resultData = Data()
        
        let channel = self.channel(host: host, port: port)
        var reqData = [UInt8](repeating: 0, count: data.count)
        data.copyBytes(to: &reqData, count: data.count)
        
        channel.onOpen {
                channel.write(reqData) { (error) in
                    guard error == nil  else {
                        receive(nil, error)
                        return
                    }
                }
            }
            .onRead{ (data) in
                resultData.append(data, count: data.count)
            }
            .onClose { (error) in
                guard error == nil  else {
                    receive(nil, error)
                    return
                }
                
                receive(resultData, nil)
            }
            .open()
    }
}
