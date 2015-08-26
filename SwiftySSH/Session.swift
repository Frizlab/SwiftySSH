//
//  Session.swift
//  SwiftySSH
//
//  Created by Vladimir Solomenchuk on 10/23/14.
//  Copyright (c) 2014 Vladimir Solomenchuk. All rights reserved.
//

import Foundation

public enum Fingerprint{
    case MD5(fingerprint: String), SHA1(fingerprint: String)
}

public enum Authentication{
    case Password(password: String)
    case PublicKey(publicKeyPath: String, privateKeyPath: String, passphrase: String)
}

typealias LIBSSH2_SESSION = COpaquePointer

private struct SSHInit {
    static let initialized = libssh2_init(0) == 0
}

private func userauthList(session: LIBSSH2_SESSION, user: String) ->[String]?
{
    let ul = libssh2_userauth_list(session, user, UInt32(user.utf8.count))
    
    if let ul = String.fromCString(ul) {
        return ul.componentsSeparatedByString(",")
    }
    
    return nil
}

public class Session {
    internal var session: LIBSSH2_SESSION = nil
    public var timeout: Double = 1000
    private let host: String
    private let port: UInt16
    private let user: String
    private var expectedFingerprint: Fingerprint?
    private var authentication: Authentication?
    var queue: dispatch_queue_t?
    internal var socket: CFSocket?
    private var connectChain = CommandChain<ErrorType?>()
    private var disconnectChain = CommandChain<ErrorType?>()
    private var keepAliveSource: dispatch_source_t!
    private var keepaliveInterval:  UInt
    private var errorCounter: UInt = 0
    private let maxErrorCounter: UInt

    
    required public init(_ user: String, host: String, port: UInt16, keepaliveInterval: UInt = 10, maxErrorCounter: UInt = 6){
        self.host = host
        self.port = port
        self.user = user
        self.keepaliveInterval = keepaliveInterval
        self.maxErrorCounter = maxErrorCounter
    }
    
    private func setupKeepAlive() {
        if keepAliveSource != nil {
            dispatch_source_cancel(keepAliveSource)
            keepAliveSource = nil
        }
        
        guard keepaliveInterval > 0 else {
            return
        }
        
        libssh2_keepalive_config (self.session, 1, UInt32(keepaliveInterval))
        
        keepAliveSource = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0, queue)
        
        let interval = UInt64(keepaliveInterval) * NSEC_PER_SEC
        dispatch_source_set_timer(keepAliveSource, dispatch_walltime(nil, 0), interval, 0);
        
        dispatch_source_set_event_handler(keepAliveSource, {
            var t = Int32(self.keepaliveInterval)
            let rc = libssh2_keepalive_send(self.session, &t)
            
            guard rc == 0 else {
                logger.debug("keepalive error \(self.sshError())")
                self.errorCounter++
                if self.errorCounter >= self.maxErrorCounter {
                    logger.debug("too many errors, closing session")
                    let error = self.sshError() ?? SSHError.NotConnected
                    self.disconnectWithError(error)
                }
                return
            }
            
            self.errorCounter = 0
            
        })
        dispatch_resume(keepAliveSource)
    }
    
    func sshError() -> SSHError? {
        
        guard session != nil else {
            return nil
        }
        
        var message: UnsafeMutablePointer<Int8> = nil
        let code = libssh2_session_last_error(session, &message, nil, 0)
        
        if code == LIBSSH2_ERROR_NONE {
            return nil
        }
        
        return SSHError.SSHError(code: code, msg: String.fromCString(message)!)
    }
    
    public func authenticate(authentication: Authentication) -> Self {
        self.authentication = authentication
        return self
    }
    
    public func checkFingerprint(fingerprint: Fingerprint) -> Self{
        self.expectedFingerprint = fingerprint
        return self
    }
    
    public func onDisconnect(handler: (Session, ErrorType?) -> Void) -> Self {
        disconnectChain.append{ (e) -> Void in
            handler(self, e)
        }
        return self
    }
    
    public func onConnect(handler: (Session, ErrorType?) -> Void) -> Self {
        connectChain.append{ (e) -> Void in
            handler(self, e)
        }
        return self
    }


    public func connect() -> Self {
        guard SSHInit.initialized else {
            disconnectChain.value = SSHError.NotConnected
            cleanup()
            return self
        }
        queue = dispatch_queue_create(nil, DISPATCH_QUEUE_SERIAL)
        dispatch_async(queue!, {
            var s = self.self
            self.session = libssh2_session_init_ex(nil, nil, nil, &s)
            
            guard let addresses = resolveHost(self.host) else {
                self.connectChain.value = SSHError.Unknown(msg: "unknown host \(self.host)")
                return
            }
            
            guard let sock = createSocket(addresses, port: self.port, timeout: self.timeout) else {
                self.connectChain.value = SSHError.Unknown(msg: "unable to connect to \(self.host):\(self.port)")
                self.cleanup()
                return
            }

            
            // Set non-blocking mode
            libssh2_session_set_blocking(self.session, 1)
            
            self.socket = sock
            
            // Start the session
            let rc = libssh2_session_handshake(self.session, CFSocketGetNative(self.socket))
            if rc != 0 {
                self.connectChain.value = self.sshError() ?? SSHError.Unknown(msg: "unable to perform handshake \(rc)")
                self.cleanup()
                return
            }
            
            //check fingerprint
            if let expectedFingerprint = self.expectedFingerprint {
                let actualFingerprint = self.fingerprint(expectedFingerprint)
                let checked: Bool
                
                switch expectedFingerprint {
                case .MD5(let x):
                    checked = actualFingerprint == x
                case .SHA1(let x):
                    checked = actualFingerprint == x
                }
                
                if !checked {
                    self.connectChain.value = SSHError.InvalidFingerprint
                    self.cleanup()
                    return
                }
            }
            
            guard let auth = self.authentication else {
                self.connectChain.value = SSHError.Unknown(msg: "authentication is not defined")
                self.cleanup()
                return
            }
            
            switch auth {
            case .Password(let password):
                if self.authenticateByPassword(password) {
                    self.connectChain.value = nil
                    self.setupKeepAlive()
                    return
                }
                
            case .PublicKey(let publicKeyPath, let privateKeyPath, let passphrase):
                if self.authenticateByPublicKey(publicKeyPath, privateKeyPath: privateKeyPath, passphrase: passphrase) {
                    self.connectChain.value = nil
                    self.setupKeepAlive()
                    return
                }

            }
            
            self.connectChain.value = self.sshError() ?? SSHError.Unknown(msg: "Unknown authentication error")
            
            self.cleanup()
        })
        
        return self
    }

    private func disconnectWithError (error: ErrorType) {
        logger.error("closing session with error: \(error)")
        disconnectChain.value = error
        cleanup()
    }
    
    public func disconnect() {
        disconnectChain.value = nil
        cleanup()
    }
    
    public func cleanup() {
        //queue pasing and releasing causes crash
        self.queue = nil
        
        if socket != nil {
            CFSocketInvalidate(socket)
            socket = nil
        }
        
        if session != nil {
            libssh2_session_disconnect_ex(session, SSH_DISCONNECT_BY_APPLICATION, "app quit", "")
            libssh2_session_free(session);
            session = nil
        }
        
        if keepAliveSource != nil {
            dispatch_source_cancel(keepAliveSource)
            keepAliveSource = nil
        }
        
        if keepAliveSource != nil {
            dispatch_source_cancel(keepAliveSource)
        }
    }
    
    public func fingerprint(hashType: Fingerprint)->String? {
        assert(session != nil, "no session")
        if self.session == nil {
            return nil;
        }
    
        switch hashType {
        case .MD5:
            if let h = libssh2_hostkey_hash(session, LIBSSH2_HOSTKEY_HASH_MD5) as UnsafePointer<Int8>? {
                return NSString (format: "%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X",
                    h[0], h[1], h[2], h[3],
                    h[4], h[5], h[6], h[7],
                    h[8], h[9], h[10], h[11],
                    h[12], h[13], h[14], h[15]) as String
            }

        case .SHA1:
            if let h = libssh2_hostkey_hash(session, LIBSSH2_HOSTKEY_HASH_SHA1) as UnsafePointer<Int8>? {
                return NSString (format: "%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X",
                    h[0], h[1], h[2], h[3],
                    h[4], h[5], h[6], h[7],
                    h[8], h[9], h[10], h[11],
                    h[12], h[13], h[14], h[15],
                    h[16], h[17], h[18], h[19]) as String
            }
        }
    }
    
    public var supportedAuthenticationMethods: [String]? {
        get {
            assert(session != nil, "no session")
            if self.session == nil {
                return nil;
            }

            return userauthList(session, user: user)
        }
    }
    
    private func authenticateByPassword(password: String)->Bool
    {
    
        if let supportedAuthenticationMethods = supportedAuthenticationMethods {
            if supportedAuthenticationMethods.contains("password")
            {
                
                let error = libssh2_userauth_password_ex(session,
                                            user.cStringUsingEncoding(NSUTF8StringEncoding)!,
                                            UInt32(user.lengthOfBytesUsingEncoding(NSUTF8StringEncoding)),
                                            password.cStringUsingEncoding(NSUTF8StringEncoding)!,
                                            UInt32(password.lengthOfBytesUsingEncoding(NSUTF8StringEncoding)),
                                            nil)
                return error == 0
            }
        }
        
        return false
    }
    
    private func authenticateByPublicKey(publicKeyPath: String, privateKeyPath: String, passphrase: String)->Bool
    {
        logger.debug("authenticating with authenticateByPublicKey, supportedAuthenticationMethods: \(supportedAuthenticationMethods)")
        if let supportedAuthenticationMethods = supportedAuthenticationMethods {
            if supportedAuthenticationMethods.contains("publickey")
            {
                let error = libssh2_userauth_publickey_fromfile_ex(session,
                    user.cStringUsingEncoding(NSUTF8StringEncoding)!,
                    UInt32(user.lengthOfBytesUsingEncoding(NSUTF8StringEncoding)),
                    publicKeyPath.cStringUsingEncoding(NSUTF8StringEncoding)!,
                    privateKeyPath.cStringUsingEncoding(NSUTF8StringEncoding)!,
                    passphrase)
                return error == 0
            }
        }
        
        return false
    }
    
    deinit {
        cleanup()
    }
}

public extension Session {
    convenience public init?(_ url: String){
        guard let parsed = NSURL(string: url), let user = parsed.user, let host = parsed.host else {
            return nil
        }
        
        self.init(user, host: host, port: parsed.port == nil ? 22 : UInt16(parsed.port!.integerValue))
    }
}