//
//  Session.swift
//  SwiftySSH
//
//  Created by Vladimir Solomenchuk on 10/23/14.
//  Copyright (c) 2014 Vladimir Solomenchuk. All rights reserved.
//

import Foundation

public enum Fingerprint {
    case sha1(String)
}

public enum Authentication {
    case password(String)
//    case publicKey(publicKeyPath: String, privateKeyPath: String, passphrase: String)
}

public enum AuthenticationMethods {
    case password
    case publicKey
    case unknown(String)
    
    init(_ value: String) {
        switch value {
        case "password":
        self = .password
        case "publickey":
        self = .publicKey
        default:
            self = .unknown(value)
        }
    }
}

public enum SessionState {
    case connected, disconnected(error: Error?), authenticated, validated, created
}

public protocol SessionDelegate: class {
    func sshSession(_ session: Session, validateFingerprint fingerprint: Fingerprint, handler: FingerprintDecisionHandler)
    func sshSession(_ session: Session, authenticate methods: [AuthenticationMethods], handler: AuthenticationDecisionHandler)
    func sshSessionConnected(_ session: Session)
    func sshSessionDisconnected(_ session: Session, error: Error?)
}

public typealias FingerprintDecisionHandler = (_ allow: Bool)->Void

public typealias AuthenticationDecisionHandler = (_ authenticate: Authentication)->Void

typealias LIBSSH2_SESSION = OpaquePointer

private struct SSHInit {
    static let initialized = libssh2_init(0) == 0
}

open class Session {
    internal var session: LIBSSH2_SESSION? = nil
    open var timeout: Double = 1000
    fileprivate let host: String
    fileprivate let port: UInt16
    fileprivate let user: String
    fileprivate var authentication: Authentication?
    var queue: OperationQueue
    internal var socket: ClientSocketType?
    fileprivate var keepAliveSource: DispatchSourceTimer!
    fileprivate var keepaliveInterval: Int
    fileprivate var errorCounter: UInt = 0
    fileprivate let maxErrorCounter: UInt
    weak var delegate: SessionDelegate?
    
    required public init(user: String, host: String, port: UInt16, keepaliveInterval: Int, maxErrorCounter: UInt){
        self.host = host
        self.port = port
        self.user = user
        self.keepaliveInterval = keepaliveInterval
        self.maxErrorCounter = maxErrorCounter
        queue = OperationQueue()
        queue.maxConcurrentOperationCount = 1
        queue.isSuspended = true
    }
    
    fileprivate func setupKeepAlive() {
        if keepAliveSource != nil {
            keepAliveSource.cancel()
            keepAliveSource = nil
        }
        
        guard keepaliveInterval > 0 else {
            return
        }
        
        libssh2_keepalive_config (self.session, 1, UInt32(keepaliveInterval))
        
        keepAliveSource = DispatchSource.makeTimerSource(queue: DispatchQueue.global(qos: .background))
        
        keepAliveSource.scheduleRepeating(deadline: DispatchTime.now(), interval: DispatchTimeInterval.seconds(keepaliveInterval))
        
        keepAliveSource.setEventHandler(handler: {
            var t = Int32(self.keepaliveInterval)
            let rc = libssh2_keepalive_send(self.session, &t)
            
            guard rc == 0 else {
                logger.debug("keepalive error \(self.sshError())")
                self.errorCounter += 1
                if self.errorCounter >= self.maxErrorCounter {
                    logger.debug("too many errors, closing session")
                    self.disconnectWithError(self.sshError())
                }
                return
            }
            
            self.errorCounter = 0
            
        })
        keepAliveSource.resume()
    }
    
    func sshError() -> SSHError {
        guard session != nil else {
            return .notConnected
        }
        
        var message: UnsafeMutablePointer<Int8>? = nil
        let code = libssh2_session_last_error(session, &message, nil, 0)
        
        if let msg = message {
            return SSHError.sshError(code: code, msg: String(cString: msg))
        }
        else {
            return SSHError.sshError(code: code, msg: "Unknown error")
        }
    }
    
    open func connect() {
        guard SSHInit.initialized else {
            disconnectWithError(sshError())
            return
        }
        
        queue.isSuspended = true
        queue.cancelAllOperations()
        
        DispatchQueue.global(qos: .background).async {
            var s = self
            self.session = libssh2_session_init_ex(nil, nil, nil, &s)
            
            do {
                self.socket = try BasicClientSocket(host: self.host, port: String(self.port))
                self.socket?.socket[socketOption: SO_NOSIGPIPE] = 1
                try self.socket?.connect()
            }
            catch {
                self.disconnectWithError(SSHError.unknown(msg: "unable to connect to \(self.host):\(self.port)"))
                return
            }
            
            
            // Start the session
            do {
                try callSSH(self, self.timeout, libssh2_session_handshake(self.session, self.socket!.socket.fileDescriptor))
            }
            catch let e {
                self.disconnectWithError(e)
                return
            }
            
            self.runEvents(.connected)
        }
    }
    
    fileprivate func runEvents(_ state: SessionState) {
        switch state {
        case .connected:
            checkFingerprint()
        case .validated:
            authenticate()
        case .authenticated:
            self.setupKeepAlive()
            self.delegate?.sshSessionConnected(self)
            self.queue.isSuspended = false
        case .created, .disconnected:
            break
        }
    }

    func authenticate() {
        guard let delegate = self.delegate, let authenticationMethods = self.authenticationMethods else {
            disconnectWithError(SSHError.authenticationFailed)
            return
        }
        delegate.sshSession(self, authenticate: authenticationMethods) { (authenticate) in
            switch authenticate {
            case .password(let password):
                do {
                    try callSSH(self, self.timeout, libssh2_userauth_password_ex(self.session,
                                                                                 self.user.cString(using: String.Encoding.utf8)!,
                                                                                 UInt32(self.user.lengthOfBytes(using: String.Encoding.utf8)),
                                                                                 password.cString(using: String.Encoding.utf8)!,
                                                                                 UInt32(password.lengthOfBytes(using: String.Encoding.utf8)),
                                                                                 nil))
                    self.runEvents(.authenticated)
                }
                catch {
                    self.disconnectWithError(SSHError.authenticationFailed)
                }
            }
        }
    }

    
    func checkFingerprint() {
        guard let delegate = self.delegate else {
            runEvents(.validated)
            return
        }
        
        delegate.sshSession(self, validateFingerprint: self.fingerprint) { (allow) in
            guard allow else {
                self.disconnectWithError(SSHError.invalidFingerprint)
                return
            }
            self.runEvents(.validated)
        }
    }
    
    func disconnectWithError (_ error: Error) {
        logger.error("closing session with error: \(error)")
        delegate?.sshSessionDisconnected(self, error: error)
        cleanup()
    }
    
    open func disconnect() {
        delegate?.sshSessionDisconnected(self, error: nil)
        cleanup()
    }
    
    fileprivate func cleanup() {
        do {
            try socket?.socket.close()
        }
        catch {
            logger.error("unable to close socket \(error)")
        }
        socket = nil
        
        if session != nil {
            libssh2_session_disconnect_ex(session, SSH_DISCONNECT_BY_APPLICATION, "app quit", "")
            libssh2_session_free(session);
            session = nil
        }
        
        if keepAliveSource != nil {
            keepAliveSource.cancel()
            keepAliveSource = nil
        }
    }
    
    open var fingerprint: Fingerprint {
        let h = libssh2_hostkey_hash(session, LIBSSH2_HOSTKEY_HASH_SHA1)!

        return .sha1(String (format: "%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X",
                h[0], h[1], h[2], h[3],
                h[4], h[5], h[6], h[7],
                h[8], h[9], h[10], h[11],
                h[12], h[13], h[14], h[15],
                h[16], h[17], h[18], h[19]))
    }
    
    open var authenticationMethods: [AuthenticationMethods]? {
        assert(session != nil, "no session")
        guard self.session != nil else { return nil }

        guard let listPtr = libssh2_userauth_list(session, user, UInt32(user.characters.count)) else {
            return nil
        }
        
        guard let listStr = String(validatingUTF8: listPtr) else {
            return nil
        }
        
        return listStr.components(separatedBy: ",").map { AuthenticationMethods($0) }
    }
    
    deinit {
        cleanup()
    }
}
