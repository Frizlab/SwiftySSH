//
//  Socket.swift
//  SwiftySSH
//
//  Created by Solomenchuk, Vlad on 8/20/15.
//  Copyright © 2015 Vladimir Solomenchuk. All rights reserved.
//

import Foundation

func resolveHost(hostName: String) -> CFArray? {
    let host = CFHostCreateWithName(kCFAllocatorDefault, hostName).takeUnretainedValue()
    guard CFHostStartInfoResolution(host, .Addresses, nil) else {
        return nil
    }
    var success: DarwinBoolean = false
    let res = CFHostGetAddressing(host, &success)?.takeUnretainedValue()
    return success ? res : nil
}

extension CFArray: SequenceType {
    public func generate() -> AnyGenerator<AnyObject> {
        var index = -1
        let maxIndex = CFArrayGetCount(self)
        return anyGenerator{
            guard ++index < maxIndex else {
                return nil
            }
            let unmanagedObject: UnsafePointer<Void> = CFArrayGetValueAtIndex(self, index)
            let rec = unsafeBitCast(unmanagedObject, AnyObject.self)
            return rec
        }
    }
}

func createSocket(addresses: CFArray, port: UInt16, timeout: CFTimeInterval) -> CFSocket? {
    for addressData in addresses {
        guard let addressData = addressData as? NSData else {
            continue
        }
        
        var storage: NSData!
        var addressFamily: Int32
        
        switch addressData.length {
        case sizeof(sockaddr_in):
            var address4 = sockaddr_in()
            addressData.getBytes(&address4, length: sizeof(sockaddr_in))
            address4.sin_port = CFSwapInt16(port)
            storage = NSData(bytes: &address4, length: Int(sizeof(sockaddr_in)))
            addressFamily = Int32(AF_INET)
        case sizeof(sockaddr_in6):
            var address6 = sockaddr_in6()
            addressData.getBytes(&address6, length: sizeof(sockaddr_in6))
            addressData.bytes
            address6.sin6_port = CFSwapInt16(port)
            storage = NSData(bytes: &address6, length: Int(sizeof(sockaddr_in6)))
            addressFamily = Int32(AF_INET6)
        default:
            logger.error("Unknown address, it's not IPv4 or IPv6!")
            continue
        }
        
        guard let socket = CFSocketCreate(kCFAllocatorDefault, addressFamily, SOCK_STREAM, IPPROTO_IP, CFSocketCallBackType.NoCallBack.rawValue, nil, nil) else{
            return nil
        }
        
        // Set NOSIGPIPE
        var set: socklen_t = 1
        guard setsockopt(CFSocketGetNative(socket), SOL_SOCKET, SO_NOSIGPIPE, &set, UInt32(sizeof(socklen_t))) == 0 else {
            CFSocketInvalidate(socket);
            return nil
        }
        
        let data = NSData(bytes: storage.bytes, length: Int(storage.length))
        guard CFSocketConnectToAddress(socket, data, timeout) == .Success else {
            CFSocketInvalidate(socket);
            return nil
        }
        
        return socket
    }
    
    return nil
}
