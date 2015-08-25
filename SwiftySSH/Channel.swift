//
//  Channel.swift
//  SwiftySSH
//
//  Created by Vladimir Solomenchuk on 10/31/14.
//  Copyright (c) 2014 Vladimir Solomenchuk. All rights reserved.
//

import Foundation

public class Channel
{
    private let remoteHost: String
    private let remotePort: UInt16
    public var channel: COpaquePointer!
    public let session: Session
    private var readSource: dispatch_source_t!
    var bufferSize = 65536
    var timeout = 60.0
    var streamId: Int32 = 0
    private var readChain = CommandChain<([UInt8]?, ErrorType?)>()
    private var closeChain = CommandChain<ErrorType?>()
    private var openChain = CommandChain<ErrorType?>()

    required public init(_ session: Session, remoteHost: String, remotePort: UInt16)
    {
        self.remoteHost = remoteHost
        self.remotePort = remotePort
        self.session = session
    }
    
    public func onRead(handler: (Channel, [UInt8]?, ErrorType?) -> Void) -> Self {
        readChain.append { (data, error) -> Void in
            handler(self, data, error)
        }
        return self
    }
    
    public func onOpen(handler: (Channel, ErrorType?) -> Void) -> Self {
        openChain.append { (error) -> Void in
            handler(self, error)
        }
        return self
    }

    public func onClose(handler: (Channel, ErrorType?) -> Void) -> Self {
        closeChain.append { (error) -> Void in
            handler(self, error)
        }
        return self
    }

    public func open() -> Self
    {
        session.onConnect { (session, error) -> Void in
            guard error == nil else {
                self.openChain.value = error
                logger.error("unable to channel \(error)")
                return
            }
            
            dispatch_async(session.queue, { () -> Void in
                logger.debug("open channel")
                libssh2_session_set_blocking(self.session.session, 1)
                self.channel = libssh2_channel_direct_tcpip_ex(self.session.session, self.remoteHost.cStringUsingEncoding(NSUTF8StringEncoding)!, Int32(self.remotePort), self.remoteHost.cStringUsingEncoding(NSUTF8StringEncoding)!, Int32(self.remotePort))
                
                guard self.channel != nil && self.channel! != nil else {
                    let error = self.session.sshError() ?? SSHError.NotConnected
                    logger.error("unable to create channel \(error)")
                    self.openChain.value = error
                    return
                }
                
                libssh2_session_set_blocking(self.session.session, 0)
                
                self.readSource = dispatch_source_create(
                    DISPATCH_SOURCE_TYPE_READ,
                    UInt(CFSocketGetNative(session.socket)), // is this going to bite us?
                    0,
                    session.queue
                )
                
                dispatch_source_set_event_handler(self.readSource) { () -> Void in
//                    logger.debug("data received")
                    let bufferSize = self.bufferSize
                    let buffer = UnsafeMutablePointer<UInt8>.alloc(bufferSize)
                    guard buffer != nil else {
                        logger.error("Out of memory")
                        self.cleanup()
                        self.readChain.value = (nil, SSHError.Unknown(msg: "Out of memory"))
                        return
                    }
                    defer {buffer.dealloc(bufferSize)}
                    let time = CFAbsoluteTimeGetCurrent() + self.timeout
                    
                    while self.channel != nil && self.channel! != nil {
                        let rc = libssh2_channel_read_ex(self.channel, self.streamId, UnsafeMutablePointer<Int8>(buffer), bufferSize)
                        
                        if rc == ssize_t(LIBSSH2_ERROR_EAGAIN) {
                            if (self.timeout > 0 && time < CFAbsoluteTimeGetCurrent()) {
                                logger.error("timeout")
                                self.readChain.value = (nil, SSHError.Timeout)
                                return
                            }
                            logger.debug("again...")
                            waitsocket(CFSocketGetNative(self.session.socket!), self.session.session)
                            break
                        }
                        else if rc < 0 {
                            logger.error("Return code of response \(rc)")
                            if (rc == ssize_t(LIBSSH2_ERROR_SOCKET_RECV)) {
                                logger.error("Error received, closing channel...")
                                self.cleanup()
                                self.readChain.value = (nil, self.session.sshError() ?? SSHError.Unknown(msg: "libssh2_channel_write \(rc)"))
                            }
                            return
                        }
                        
//                        logger.debug("got \(rc) bytes")
                        let data = Array(UnsafeBufferPointer(start: buffer, count: rc))
                        self.readChain.value = (data, nil)
                        
                        if (libssh2_channel_eof(self.channel) == 1) {
                            logger.debug("Host EOF received")
                            self.close()
                            return
                        }
                    }
                }
                
                dispatch_resume(self.readSource)
                self.openChain.value = nil
            })
        }

        return self
    }
    
    private func cleanup(){
        if self.channel != nil && self.channel! != nil {
            logger.debug("cleanup")
            libssh2_channel_close(self.channel)
            libssh2_channel_wait_closed(self.channel)
            libssh2_channel_free(self.channel)
            self.channel = nil
            dispatch_source_cancel(self.readSource)
            self.readSource = nil
        }
    }
    
    public func close() {
        logger.debug("channel closed")
        cleanup()
        closeChain.value = nil
    }
    
    public func write(buffer: [UInt8], handler:(ErrorType?) -> Void) {
        guard self.channel != nil && self.channel! != nil else {
            handler(SSHError.NotConnected)
            return
        }
        
        dispatch_async(session.queue) { () -> Void in
            var rc: ssize_t
            
            var wr: ssize_t = 0
            let len = buffer.count
            let time = CFAbsoluteTimeGetCurrent() + self.timeout
            
            while wr < len  {
                rc = libssh2_channel_write_ex(self.channel, self.streamId, UnsafePointer(buffer) + wr, len - wr)
                
                if LIBSSH2_ERROR_EAGAIN == Int32(rc) {
                    if (self.timeout > 0 && time < CFAbsoluteTimeGetCurrent()) {
                        logger.error("timeout")
                        handler(SSHError.Timeout)
                        return
                    }
                    logger.debug("again...")
                    waitsocket(CFSocketGetNative(self.session.socket!), self.session.session)
                    continue;
                }
                
                if  rc < 0 {
                    let error = self.session.sshError() ?? SSHError.Unknown(msg: "libssh2_channel_write \(rc)")
                    logger.error("libssh2_channel_write \(error)")
                    handler(error)
                    return
                }
                
//                logger.debug("sent \(rc) bytes")
                wr += rc
            }
            
            handler(nil)
        }
   }
    
    deinit {
        cleanup()
    }
}

public extension Channel {
    public func write(buffer: String, handler:(ErrorType?) -> Void) {
        write([UInt8](buffer.utf8), handler: handler)
    }
    
    public func send(data: NSData, response: (NSData?, ErrorType?) -> Void) {
        let dataBuffer = NSMutableData(capacity: 65535)!
        self.onOpen { (channel, error) -> Void in
            guard error == nil else{
                response(nil, error)
                return
            }
            
            //write data
            let count = data.length
            var array = [UInt8](count: count, repeatedValue: 0)
            
            // copy bytes into array
            data.getBytes(&array, length:count * sizeof(UInt8))
            self.write(array) { (error) -> Void in
                if error != nil {
                    response(nil, error)
                }
            }
        }
        .onRead({ (_, buffer, error) -> Void in
            guard let buffer = buffer where error == nil else {
                response(nil, error)
                return
            }
            
            dataBuffer.appendBytes(UnsafePointer<Void>(buffer), length: buffer.count)
        })
        .onClose{ (channel, error) -> Void in
            guard error == nil else {
                response(nil, error)
                return
            }
            response(dataBuffer, error)
        }
        .open()
    }
}