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
    public var channel: OpaquePointer!
    public let session: Session
    private var readSource: DispatchSourceRead!
    var bufferSize = 65536
    var timeout = 60.0
    var streamId: Int32 = 0
    private var readChain = CommandChain<([UInt8]?, ErrorProtocol?)>()
    private var closeChain = CommandChain<ErrorProtocol?>()
    private var openChain = CommandChain<ErrorProtocol?>()

    required public init(_ session: Session, remoteHost: String, remotePort: UInt16)
    {
        self.remoteHost = remoteHost
        self.remotePort = remotePort
        self.session = session
    }
    
    public func onRead(_ handler: (Channel, [UInt8]?, ErrorProtocol?) -> Void) -> Self {
        readChain.append { (data, error) -> Void in
            handler(self, data, error)
        }
        return self
    }
    
    public func onOpen(_ handler: (Channel, ErrorProtocol?) -> Void) -> Self {
        openChain.append { (error) -> Void in
            handler(self, error)
        }
        return self
    }

    public func onClose(_ handler: (Channel, ErrorProtocol?) -> Void) -> Self {
        closeChain.append { (error) -> Void in
            handler(self, error)
        }
        return self
    }

    @discardableResult
    public func open() -> Self
    {
        session.onConnect { (session, error) -> Void in
            guard let queue = session.queue where error == nil else {
                let error = error ?? SSHError.notConnected
                self.openChain.value = error
                logger.error("unable to create channel \(error)")
                return
            }
            
            
            queue.async(execute: { () -> Void in
                logger.debug("open channel")
                
                do {
                    self.channel = try callSSHNotNull(self.session,
                                                      self.timeout,
                                                      libssh2_channel_direct_tcpip_ex(self.session.session,
                                                                                      self.remoteHost.cString(using: String.Encoding.utf8)!,
                                                                                      Int32(self.remotePort),
                                                                                      self.remoteHost.cString(using: String.Encoding.utf8)!,
                                                                                      Int32(self.remotePort)
                                                        )
                                    )
                }
                catch let e{
                    logger.error("unable to create channel \(error)")
                    self.openChain.value = error
                    return
                }
                
                self.readSource = DispatchSource.read(fileDescriptor: session.socket!.socket.fileDescriptor, queue: session.queue)
                
                self.readSource.setEventHandler { () -> Void in
//                    logger.debug("data received")
                    let bufferSize = self.bufferSize
                    let buffer = UnsafeMutablePointer<UInt8>(allocatingCapacity: bufferSize)
                    defer {buffer.deallocateCapacity(bufferSize)}
                    let time = CFAbsoluteTimeGetCurrent() + self.timeout
                    
                    while self.channel != nil {
                        let rc = libssh2_channel_read_ex(self.channel, self.streamId, UnsafeMutablePointer<Int8>(buffer), bufferSize)
                        
                        if rc == ssize_t(LIBSSH2_ERROR_EAGAIN) {
                            if (self.timeout > 0 && time < CFAbsoluteTimeGetCurrent()) {
                                logger.error("timeout")
                                self.readChain.value = (nil, SSHError.timeout)
                                return
                            }
                            logger.debug("again...")
                            waitsocket(self.session.socket!.socket.fileDescriptor, self.session.session)
                            break
                        }
                        else if rc < 0 {
                            logger.error("Return code of response \(rc)")
                            if (rc == ssize_t(LIBSSH2_ERROR_SOCKET_RECV)) {
                                logger.error("Error received, closing channel...")
                                self.cleanup()
                                self.readChain.value = (nil, self.session.sshError() ?? SSHError.unknown(msg: "libssh2_channel_read_ex \(rc)"))
                            }
                            return
                        }
                        
//                        logger.debug("got \(rc) bytes")
                        let data = Array(UnsafeBufferPointer(start: buffer, count: rc))
                        self.readChain.value = (data, nil)
                        
                        
                        let eof = libssh2_channel_eof(self.channel)
                        
                        if eof == 1 {
                            logger.debug("channel EOF received")
                            self.close()
                            return
                        }
                        else if eof < 0 {
                            logger.error("Error received, closing channel...")
                            self.cleanup()
                            self.readChain.value = (nil, self.session.sshError() ?? SSHError.unknown(msg: "libssh2_channel_eof \(rc)"))
                            return
                        }
                    }
                }
                
                self.readSource.resume()
                self.openChain.value = nil
            })
        }

        return self
    }
    
    private func cleanup(){
        if self.channel != nil {
            logger.debug("channel cleanup")
            libssh2_channel_close(self.channel)
            libssh2_channel_wait_closed(self.channel)
            libssh2_channel_free(self.channel)
            self.channel = nil
            self.readSource.cancel()
            self.readSource = nil
        }
    }
    
    public func close() {
        logger.debug("channel closed")
        cleanup()
        closeChain.value = nil
    }
    
    public func write(_ buffer: [UInt8], handler:(ErrorProtocol?) -> Void) {
        guard let queue = session.queue where self.channel != nil else {
            handler(SSHError.notConnected)
            return
        }
        
        queue.async { () -> Void in
            var rc: ssize_t
            
            var wr: ssize_t = 0
            let len = buffer.count
            let time = CFAbsoluteTimeGetCurrent() + self.timeout
            
            while wr < len  {
                rc = libssh2_channel_write_ex(self.channel, self.streamId, UnsafePointer(buffer) + wr, len - wr)
                
                if LIBSSH2_ERROR_EAGAIN == Int32(rc) {
                    if (self.timeout > 0 && time < CFAbsoluteTimeGetCurrent()) {
                        logger.error("timeout")
                        handler(SSHError.timeout)
                        return
                    }
                    logger.debug("again...")
                    waitsocket(self.session.socket!.socket.fileDescriptor, self.session.session)
                    continue;
                }
                
                if  rc < 0 {
                    let error = self.session.sshError() ?? SSHError.unknown(msg: "libssh2_channel_write \(rc)")
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
    public func write(_ buffer: String, handler:(ErrorProtocol?) -> Void) {
        write([UInt8](buffer.utf8), handler: handler)
    }
    
    public func send(_ data: Data, response: (Data?, ErrorProtocol?) -> Void) {
        let dataBuffer = NSMutableData(capacity: 65535)!
        self.onOpen { (channel, error) -> Void in
            guard error == nil else{
                response(nil, error)
                return
            }
            
            //write data
            let count = data.count
            var array = [UInt8](repeating: 0, count: count)
            
            // copy bytes into array
            (data as NSData).getBytes(&array, length:count * sizeof(UInt8.self))
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
            
            dataBuffer.append(UnsafePointer<Void>(buffer), length: buffer.count)
        })
        .onClose{ (channel, error) -> Void in
            guard error == nil else {
                response(nil, error)
                return
            }
            response(dataBuffer as Data, error)
        }
        .open()
    }
}
