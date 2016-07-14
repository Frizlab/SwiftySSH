//
//  Session.swift
//  SwiftySSH
//
//  Created by Vladimir Solomenchuk on 10/23/14.
//  Copyright (c) 2014 Vladimir Solomenchuk. All rights reserved.
//

import Foundation

public enum Fingerprint{
    case md5(fingerprint: String), sha1(fingerprint: String)
}

public enum Authentication{
    case password(password: String)
    case publicKey(publicKeyPath: String, privateKeyPath: String, passphrase: String)
}

typealias LIBSSH2_SESSION = OpaquePointer

private struct SSHInit {
    static let initialized = libssh2_init(0) == 0
}

private func userauthList(_ session: LIBSSH2_SESSION, user: String) ->[String]?
{
    let ul = libssh2_userauth_list(session, user, UInt32(user.utf8.count))
    
    if let ul = String(validatingUTF8: ul!) {
        return ul.components(separatedBy: ",")
    }
    
    return nil
}

public class Session {
    internal var session: LIBSSH2_SESSION? = nil
    public var timeout: Double = 1000
    private let host: String
    private let port: UInt16
    private let user: String
    private var expectedFingerprint: Fingerprint?
    private var authentication: Authentication?
    var queue: DispatchQueue!
    internal var socket: ClientSocketType?
    private var connectChain = CommandChain<ErrorProtocol?>()
    private var disconnectChain = CommandChain<ErrorProtocol?>()
    private var keepAliveSource: DispatchSourceTimer!
    private var keepaliveInterval:  Int
    private var errorCounter: UInt = 0
    private let maxErrorCounter: UInt

    
    required public init(_ user: String, host: String, port: UInt16, keepaliveInterval: Int = 10, maxErrorCounter: UInt = 6){
        self.host = host
        self.port = port
        self.user = user
        self.keepaliveInterval = keepaliveInterval
        self.maxErrorCounter = maxErrorCounter
    }
    
    private func setupKeepAlive() {
        if keepAliveSource != nil {
            keepAliveSource.cancel()
            keepAliveSource = nil
        }
        
        guard keepaliveInterval > 0 else {
            return
        }
        
        libssh2_keepalive_config (self.session, 1, UInt32(keepaliveInterval))
        
        keepAliveSource = DispatchSource.timer(queue: queue)
        
        keepAliveSource.scheduleRepeating(deadline: DispatchTime.now(), interval: DispatchTimeInterval.seconds(keepaliveInterval))
        
        keepAliveSource.setEventHandler(handler: {
            var t = Int32(self.keepaliveInterval)
            let rc = libssh2_keepalive_send(self.session, &t)
            
            guard rc == 0 else {
                logger.debug("keepalive error \(self.sshError())")
                self.errorCounter += 1
                if self.errorCounter >= self.maxErrorCounter {
                    logger.debug("too many errors, closing session")
                    let error = self.sshError() ?? SSHError.notConnected
                    self.disconnectWithError(error)
                }
                return
            }
            
            self.errorCounter = 0
            
        })
        keepAliveSource.resume()
    }
    
    func sshError() -> SSHError? {
        
        guard session != nil else {
            return nil
        }
        
        var message: UnsafeMutablePointer<Int8>? = nil
        let code = libssh2_session_last_error(session, &message, nil, 0)
        
        if code == LIBSSH2_ERROR_NONE {
            return nil
        }
        
        if let msg = message {
            return SSHError.sshError(code: code, msg: String(cString: msg))
        }
        else {
            return SSHError.sshError(code: code, msg: "Unknown error")
        }
    }
    
    @discardableResult
    public func authenticate(_ authentication: Authentication) -> Self {
        self.authentication = authentication
        return self
    }
    
    @discardableResult
    public func checkFingerprint(_ fingerprint: Fingerprint) -> Self{
        self.expectedFingerprint = fingerprint
        return self
    }
    
    @discardableResult
    public func onDisconnect(_ handler: (Session, ErrorProtocol?) -> Void) -> Self {
        disconnectChain.append{ (e) -> Void in
            handler(self, e)
        }
        return self
    }
    
    @discardableResult
    public func onConnect(_ handler: (Session, ErrorProtocol?) -> Void) -> Self {
        connectChain.append{ (e) -> Void in
            handler(self, e)
        }
        return self
    }

    @discardableResult
    public func connect() -> Self {
        guard SSHInit.initialized else {
            connectChain.value = sshError()
            cleanup()
            return self
        }
        queue = DispatchQueue(label: "net.aramzamzam.nswiftyssh", attributes: DispatchQueueAttributes.serial)
        queue!.async{
            var s = self
            self.session = libssh2_session_init_ex(nil, nil, nil, &s)
            
            do {
                self.socket = try BasicClientSocket(host: self.host, port: String(self.port))
                self.socket?.socket[socketOption: SO_NOSIGPIPE] = 1
                try self.socket?.connect()
            }
            catch {
                self.connectChain.value = SSHError.unknown(msg: "unable to connect to \(self.host):\(self.port)")
                self.cleanup()
                return
            }

            
            // Start the session
            do {
                try callSSH(self, self.timeout, libssh2_session_handshake(self.session, self.socket!.socket.fileDescriptor))
            }
            catch let e {
                self.connectChain.value = e
                self.cleanup()
                return
            }
            
            //check fingerprint
            if let expectedFingerprint = self.expectedFingerprint {
                let actualFingerprint = self.fingerprint(expectedFingerprint)
                let checked: Bool
                
                switch expectedFingerprint {
                case .md5(let x):
                    checked = actualFingerprint == x
                case .sha1(let x):
                    checked = actualFingerprint == x
                }
                
                if !checked {
                    self.connectChain.value = SSHError.invalidFingerprint
                    self.cleanup()
                    return
                }
            }
            
            guard let auth = self.authentication else {
                self.connectChain.value = SSHError.unknown(msg: "authentication is not defined")
                self.cleanup()
                return
            }
            
            switch auth {
            case .password(let password):
                if self.authenticateByPassword(password) {
                    self.connectChain.value = nil
                    self.setupKeepAlive()
                    return
                }
                
            case .publicKey(let publicKeyPath, let privateKeyPath, let passphrase):
                if self.authenticateByPublicKey(publicKeyPath, privateKeyPath: privateKeyPath, passphrase: passphrase) {
                    self.connectChain.value = nil
                    self.setupKeepAlive()
                    return
                }

            }
            
            self.connectChain.value = self.sshError() ?? SSHError.unknown(msg: "Unknown authentication error")
            
            self.cleanup()
        }
        
        return self
    }

    private func disconnectWithError (_ error: ErrorProtocol) {
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
    
    public func fingerprint(_ hashType: Fingerprint)->String? {
        assert(session != nil, "no session")
        if self.session == nil {
            return nil;
        }
    
        switch hashType {
        case .md5:
            if let h = libssh2_hostkey_hash(session, LIBSSH2_HOSTKEY_HASH_MD5) as UnsafePointer<Int8>? {
                return NSString (format: "%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X",
                    h[0], h[1], h[2], h[3],
                    h[4], h[5], h[6], h[7],
                    h[8], h[9], h[10], h[11],
                    h[12], h[13], h[14], h[15]) as String
            }

        case .sha1:
            if let h = libssh2_hostkey_hash(session, LIBSSH2_HOSTKEY_HASH_SHA1) as UnsafePointer<Int8>? {
                return NSString (format: "%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X",
                    h[0], h[1], h[2], h[3],
                    h[4], h[5], h[6], h[7],
                    h[8], h[9], h[10], h[11],
                    h[12], h[13], h[14], h[15],
                    h[16], h[17], h[18], h[19]) as String
            }
        }
        
        return nil
    }
    
    public var supportedAuthenticationMethods: [String]? {
        get {
            assert(session != nil, "no session")
            if self.session == nil {
                return nil;
            }

            return userauthList(session!, user: user)
        }
    }
    
    private func authenticateByPassword(_ password: String)->Bool
    {
    
        if let supportedAuthenticationMethods = supportedAuthenticationMethods {
            if supportedAuthenticationMethods.contains("password")
            {
                
                do {
                    try callSSH(self, self.timeout, libssh2_userauth_password_ex(session,
                        user.cString(using: String.Encoding.utf8)!,
                        UInt32(user.lengthOfBytes(using: String.Encoding.utf8)),
                        password.cString(using: String.Encoding.utf8)!,
                        UInt32(password.lengthOfBytes(using: String.Encoding.utf8)),
                        nil))
                    return true
                }
                catch {
                    return false
                }
            }
        }
        
        return false
    }
    
    private func authenticateByPublicKey(_ publicKeyPath: String, privateKeyPath: String, passphrase: String)->Bool
    {
        logger.debug("authenticating with authenticateByPublicKey, supportedAuthenticationMethods: \(supportedAuthenticationMethods)")
        if let supportedAuthenticationMethods = supportedAuthenticationMethods {
            if supportedAuthenticationMethods.contains("publickey")
            {
                do {
                    try callSSH(self, self.timeout, libssh2_userauth_publickey_fromfile_ex(session,
                        user.cString(using: String.Encoding.utf8)!,
                        UInt32(user.lengthOfBytes(using: String.Encoding.utf8)),
                        publicKeyPath.cString(using: String.Encoding.utf8)!,
                        privateKeyPath.cString(using: String.Encoding.utf8)!,
                        passphrase))
                    
                    return true
                }
                catch {
                    return false
                }
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
        guard let parsed = URL(string: url), let user = parsed.user, let host = parsed.host else {
            return nil
        }
        
        self.init(user, host: host, port: (parsed as NSURL).port == nil ? 22 : UInt16((parsed as NSURL).port!.intValue))
    }
}
