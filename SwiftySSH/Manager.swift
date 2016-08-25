//
//  Manager.swift
//  SwiftySSH
//
//  Created by Solomenchuk, Vlad on 7/31/15.
//  Copyright © 2015 Vladimir Solomenchuk. All rights reserved.
//

import Foundation

/// Used to represent whether a request was successful or encountered an error.
///
/// - success: The request and all post processing operations were successful resulting in the serialization of the
///            provided associated value.
///
/// - failure: The request encountered an error resulting in a failure. The associated values are the original data
///            provided by the server as well as the error that caused the failure.
public enum Result<Value, Error: Swift.Error> {
    case success(Value)
    case failure(Error)
    
    /// Returns `true` if the result is a success, `false` otherwise.
    public var isSuccess: Bool {
        switch self {
        case .success:
            return true
        case .failure:
            return false
        }
    }
    
    /// Returns `true` if the result is a failure, `false` otherwise.
    public var isFailure: Bool {
        return !isSuccess
    }
    
    /// Returns the associated value if the result is a success, `nil` otherwise.
    public var value: Value? {
        switch self {
        case .success(let value):
            return value
        case .failure:
            return nil
        }
    }
    
    /// Returns the associated error value if the result is a failure, `nil` otherwise.
    public var error: Error? {
        switch self {
        case .success:
            return nil
        case .failure(let error):
            return error
        }
    }
}

open class Manager {
    open let session: ManagedSession

    public init(user: String, host: String, port: UInt16, keepaliveInterval: Int = 10, maxErrorCounter: UInt = 3) {
        session = ManagedSession(user: user, host: host, port: port, keepaliveInterval: keepaliveInterval, maxErrorCounter: maxErrorCounter)
    }
    
    open func channel(_ host: String = "127.0.0.1", port: UInt16) -> ManagedChannel {
        return ManagedChannel(session: session, host: host, port: port)
    }
    
    deinit {
        session.disconnect()
    }
    
    open class ManagedChannel: Channel, SwiftySSH.ChannelDelegate {
        fileprivate var onOpenHandler: (() -> Void)?
        fileprivate var onClose: ((Error?) -> Void)?
        fileprivate var onRead: ((Array<UInt8>) -> Void)?
        
        required public init(session: Session, host: String, port: UInt16) {
            super.init(session: session, host: host, port: port)
            self.delegate = self
        }
        
        open func sshChannelOpened(_ channel: Channel) {
            onOpenHandler?()
        }
        
        open func sshChannelClosed(_ channel: Channel, error: Error?) {
            onClose?(error)
        }
        
        open func sshChannel(_ channel: Channel, received data: Array<UInt8>) {
            onRead?(data)
        }
        
        @discardableResult
        open func onOpen(_ handler: @escaping () -> Void) -> Self {
            onOpenHandler = handler
            return self
        }
        
        @discardableResult
        open func onClose(_ handler: @escaping (Error?) -> Void) -> Self {
            onClose = handler
            
            return self
        }
        
        @discardableResult
        open func onRead(_ handler: @escaping (Array<UInt8>) -> Void) -> Self {
            onRead = handler
            
            return self
        }
    }
    
    open class ManagedSession: Session, SwiftySSH.SessionDelegate {
        fileprivate var onValidateHandler: ((Fingerprint, FingerprintDecisionHandler) -> Void)?
        fileprivate var onDisconnectHandler: ((Error?) -> Void)?
        fileprivate var onConnectHandler: (() -> Void)?
        fileprivate var onAuthenticateHandler: (([AuthenticationMethods], AuthenticationDecisionHandler) -> Void)?

        
        required public init(user: String, host: String, port: UInt16, keepaliveInterval: Int, maxErrorCounter: UInt) {
            super.init(user: user, host: host, port: port, keepaliveInterval: keepaliveInterval, maxErrorCounter: maxErrorCounter)
            delegate = self
        }

        open func sshSession(_ session: Session, validateFingerprint fingerprint: Fingerprint, handler: FingerprintDecisionHandler) {
            onValidateHandler?(fingerprint, handler)
        }
        
        open func sshSession(_ session: Session, authenticate methods: [AuthenticationMethods], handler: AuthenticationDecisionHandler) {
            onAuthenticateHandler?(methods, handler)
        }
        
        open func sshSessionConnected(_ session: Session) {
            onConnectHandler?()
        }
        
        open func sshSessionDisconnected(_ session: Session, error: Error?) {
            
            onDisconnectHandler?(error)
        }
        
        @discardableResult
        open func onValidate(_ handler: @escaping (Fingerprint, FingerprintDecisionHandler) -> Void) -> Self {
            onValidateHandler = handler
            
            return self
        }
        
        @discardableResult
        open func onAuthenticate(_ handler: @escaping ([AuthenticationMethods], AuthenticationDecisionHandler) -> Void) -> Self {
            onAuthenticateHandler = handler
            
            return self
        }
        
        @discardableResult
        open func onConnect(_ handler: @escaping () -> Void) -> Self {
            onConnectHandler = handler
            
            return self
        }
        
        @discardableResult
        open func onDisconnect(_ handler: @escaping (Error?) -> Void) -> Self {
            onDisconnectHandler = handler
            
            return self
        }
    }
}

extension Manager {
    public func request(_ host: String = "127.0.0.1", port: UInt16, send data: Data, receive: @escaping (Result<Data, NSError>) -> Void) {
        
        var resultData = Data()
        
        let channel = self.channel(host, port: port)
        var reqData = [UInt8](repeating: 0, count: data.count)
        data.copyBytes(to: &reqData, count: data.count)
        
        channel.onOpen {
                channel.write(reqData) { (error) in
                    guard error == nil  else {
                        receive(.failure(error! as NSError))
                        return
                    }
                }
            }
            .onRead{ (data) in
                resultData.append(data, count: data.count)
            }
            .onClose { (error) in
                guard error == nil  else {
                    receive(.failure(error! as NSError))
                    return
                }
                
                receive(.success(resultData))
            }
            .open()
    }
}
