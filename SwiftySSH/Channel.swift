//
//  Channel.swift
//  SwiftySSH
//
//  Created by Vladimir Solomenchuk on 10/31/14.
//  Copyright (c) 2014 Vladimir Solomenchuk. All rights reserved.
//

import Foundation

public protocol ChannelDelegate: class {
    func sshChannelOpened(channel: Channel)
    func sshChannelClosed(channel: Channel, error: ErrorProtocol?)
    func sshChannel(channel: Channel, received data: Array<UInt8>)
}

public class Channel {
    private let host: String
    private let port: UInt16
    public var channel: OpaquePointer!
    public let session: Session
    private var readSource: DispatchSourceRead!
    var bufferSize = 65536
    var timeout = 60.0
    var streamId: Int32 = 0
    weak var delegate: ChannelDelegate?

    required public init(session: Session, host: String, port: UInt16) {
        self.host = host
        self.port = port
        self.session = session
    }
    
    public func open() {
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
                    myself.delegate?.sshChannelClosed(channel: myself, error: error)
                    return
                }

                myself.delegate?.sshChannelOpened(channel: myself)
                myself.openReadChannel()
        }
    }
    
    func openReadChannel() {
        let queue = DispatchQueue.global(attributes: DispatchQueue.GlobalAttributes.qosBackground)
        self.readSource = DispatchSource.read(fileDescriptor: self.session.socket!.socket.fileDescriptor, queue: queue)
        
        self.readSource.setEventHandler { [weak self] () -> Void in
            guard let myself = self else { return }
            
            //                    logger.debug("data received")
            let bufferSize = myself.bufferSize
            let buffer = UnsafeMutablePointer<UInt8>(allocatingCapacity: bufferSize)
            defer {buffer.deallocateCapacity(bufferSize)}
            let time = CFAbsoluteTimeGetCurrent() + myself.timeout
            
            while myself.channel != nil {
                let rc = libssh2_channel_read_ex(myself.channel, myself.streamId, UnsafeMutablePointer<Int8>(buffer), bufferSize)
                
                if rc == ssize_t(LIBSSH2_ERROR_EAGAIN) {
                    if (myself.timeout > 0 && time < CFAbsoluteTimeGetCurrent()) {
                        let error = SSHError.timeout
                        logger.error("Error while reading: \(error)")
                        myself.delegate?.sshChannelClosed(channel: myself, error: error)
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
                        myself.delegate?.sshChannelClosed(channel: myself, error: error)
                        myself.cleanup()
                    }
                    return
                }
                
                //                        logger.debug("got \(rc) bytes")
                let data = Array(UnsafeBufferPointer(start: buffer, count: rc))
                myself.delegate?.sshChannel(channel: myself, received: data)
                
                let eof = libssh2_channel_eof(myself.channel)
                
                if eof == 1 {
                    logger.debug("channel EOF received")
                    myself.close()
                    return
                }
                else if eof < 0 {
                    let error = myself.session.sshError() ?? SSHError.unknown(msg: "libssh2_channel_eof \(rc)")
                    logger.error("Error while reading: \(error)")
                    myself.delegate?.sshChannelClosed(channel: myself, error: error)
                    myself.cleanup()
                    return
                }
            }
        }
        
        self.readSource.resume()
    }

    private func cleanup() {
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
    
    public func close() {
        logger.debug("channel closed")
        cleanup()
        delegate?.sshChannelClosed(channel: self, error: nil)
    }
    
    public func write(_ buffer: [UInt8], handler:(ErrorProtocol?) -> Void) {
        guard self.channel != nil else {
            handler(SSHError.notConnected)
            return
        }
        
        session.queue.addOperation { () -> Void in
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

public extension Session {
    public func channel(host: String, port: UInt16) -> Channel {
        return Channel(session: self, host: host, port: port)
    }
}
