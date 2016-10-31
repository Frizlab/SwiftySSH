//
//  Channel.swift
//  SwiftySSH
//
//  Created by Vladimir Solomenchuk on 10/31/14.
//  Copyright (c) 2014 Vladimir Solomenchuk. All rights reserved.
//

import Foundation

public protocol ChannelDelegate: class {
    func sshChannelOpened(_ channel: Channel)
    func sshChannelClosed(_ channel: Channel, error: Error?)
    func sshChannel(_ channel: Channel, received data: Array<UInt8>)
}

open class Channel {
    fileprivate let host: String
    fileprivate let port: UInt16
    open var channel: OpaquePointer!
    open let session: Session
    fileprivate var readSource: DispatchSourceRead!
    var bufferSize = 65536
    var timeout = 60.0
    var streamId: Int32 = 0
    weak var delegate: ChannelDelegate?

    required public init(session: Session, host: String, port: UInt16) {
        self.host = host
        self.port = port
        self.session = session
    }
    
    open func open() {
            session.queue.addOperation { [weak self] () -> Void in
                guard let myself = self else { return }
                
                logger.debug("open channel")
                
                do {
                    myself.channel = try callSSHNotNull(myself.session,
                                                      myself.timeout,
                                                      libssh2_channel_direct_tcpip_ex(myself.session.session,
                                                                                      myself.host.cString(using: String.Encoding.utf8)!,
                                                                                      Int32(myself.port),
                                                                                      myself.host.cString(using: String.Encoding.utf8)!,
                                                                                      Int32(myself.port)
                                                        )
                                    )
                }
                catch {
                    logger.error("unable to create channel \(error)")
                    myself.delegate?.sshChannelClosed(myself, error: error)
                    return
                }

                myself.delegate?.sshChannelOpened(myself)
                myself.openReadChannel()
        }
    }
    
    func openReadChannel() {
        let queue = DispatchQueue.global(qos: .background)
        self.readSource = DispatchSource.makeReadSource(fileDescriptor: self.session.socket!.socket.fileDescriptor, queue: queue)
        
        self.readSource.setEventHandler { [weak self] () -> Void in
            self?.session.queue.addOperation {
                guard let myself = self else { return }

                //                    logger.debug("data received")
                let bufferSize = myself.bufferSize
                let buffer = UnsafeMutablePointer<Int8>.allocate(capacity: bufferSize)
                defer {buffer.deallocate(capacity: bufferSize)}
                let time = CFAbsoluteTimeGetCurrent() + myself.timeout
                
                
                while myself.channel != nil {
                    let rc = libssh2_channel_read_ex(myself.channel, myself.streamId, buffer, bufferSize)
                    
                    if rc == ssize_t(LIBSSH2_ERROR_EAGAIN) {
                        if (myself.timeout > 0 && time < CFAbsoluteTimeGetCurrent()) {
                            let error = SSHError.timeout
                            logger.error("Error while reading: \(error)")
                            myself.delegate?.sshChannelClosed(myself, error: error)
                            myself.cleanup()
                            return
                        }
                        logger.debug("again...")
                        waitsocket(myself.session.socket!.socket.fileDescriptor, myself.session.session)
                        break
                    }
                    else if rc < 0 {
                        logger.error("Error reading response \(rc)")
                        if (rc == ssize_t(LIBSSH2_ERROR_SOCKET_RECV)) {
                            let error = myself.session.sshError() ?? SSHError.unknown(msg: "libssh2_channel_read_ex \(rc)")
                            logger.error("Error while reading: \(error)")
                            myself.delegate?.sshChannelClosed(myself, error: error)
                            myself.cleanup()
                        }
                        return
                    }
                    
                    //logger.debug("got \(rc) bytes")
                    
                    
                    let bufferPointer = UnsafePointer(buffer).withMemoryRebound(to: UInt8.self, capacity: rc) { $0 }
                    let data = Array(UnsafeBufferPointer(start: bufferPointer, count: rc))
                    myself.delegate?.sshChannel(myself, received: data)
                    
                    let eof = libssh2_channel_eof(myself.channel)
                    
                    if eof == 1 {
                        logger.debug("channel EOF received")
                        myself.close()
                        return
                    }
                    else if eof < 0 {
                        let error = myself.session.sshError() ?? SSHError.unknown(msg: "libssh2_channel_eof \(rc)")
                        logger.error("Error while reading: \(error)")
                        myself.delegate?.sshChannelClosed(myself, error: error)
                        myself.cleanup()
                        return
                    }
                }
            }
        }
        
        self.readSource.resume()
    }

    fileprivate func cleanup() {
        if self.channel != nil {
            logger.debug("channel cleanup")
            libssh2_channel_close(self.channel)
            libssh2_channel_wait_closed(self.channel)
//            libssh2_channel_free(self.channel)
            self.channel = nil
            self.readSource.cancel()
            self.readSource = nil
        }
    }
    
    open func close() {
        logger.debug("channel closed")
        cleanup()
        delegate?.sshChannelClosed(self, error: nil)
    }
    
    open func write(_ buffer: [UInt8], handler:@escaping (Error?) -> Void) {
        guard self.channel != nil else {
            handler(SSHError.notConnected)
            return
        }
        
        session.queue.addOperation { () -> Void in
            var rc: ssize_t
            
            var wr: ssize_t = 0
            let len = buffer.count
            let time = CFAbsoluteTimeGetCurrent() + self.timeout
            
            let bufferPointer = UnsafePointer(buffer).withMemoryRebound(to: Int8.self, capacity: buffer.count) { $0 }
            while wr < len  {
                rc = libssh2_channel_write_ex(self.channel, self.streamId, bufferPointer + wr, len - wr)
                
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

public extension Session {
    public func channel(_ host: String, port: UInt16) -> Channel {
        return Channel(session: self, host: host, port: port)
    }
}
