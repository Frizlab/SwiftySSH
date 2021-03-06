//
//  SocketAddress.swift
//  SocketWrapper
//
//  Created by Marco Masser on 2016-03-04.
//  Copyright © 2016 Objective Development. All rights reserved.
//

import Darwin

/// A wrapper around the `sockaddr`, `sockaddr_in`, and `sockaddr_in6` family of structs.
///
/// It provides storage for any socket address and implements methods that allow using that
/// storage as a pointer to a "generic" `sockaddr` struct.
enum SocketAddress {

    /// An IPv4 address represented by a `sockaddr_in`.
    case version4(address: sockaddr_in)

    /// An IPv6 address represented by a `sockaddr_in6`.
    case version6(address: sockaddr_in6)

    /// The length of a `sockaddr_in` as the appropriate type for low-level APIs.
    static var lengthOfVersion4: socklen_t {
        return socklen_t(MemoryLayout<sockaddr_in>.size)
    }

    /// The length of a `sockaddr_in6` as the appropriate type for low-level APIs.
    static var lengthOfVersion6: socklen_t {
        return socklen_t(MemoryLayout<sockaddr_in6>.size)
    }

    /// Creates either a `Version4` or `Version6` socket address, depending on what `addressProvider` does.
    ///
    /// This initializer calls the given `addressProvider` with an `UnsafeMutablePointer<sockaddr>` that points to a buffer
    /// that can hold either a `sockaddr_in` or a `sockaddr_in6`. After `addressProvider` returns, the pointer is
    /// expected to contain an address. For that address, a `SocketAddress` is then created.
    ///
    /// This initializer is intended to be used with `Darwin.accept()`.
    ///
    /// - Parameter addressProvider: A closure that will be called and is expected to fill in an address into the given buffer.
//    init( addressProvider: @escaping (UnsafeMutablePointer<sockaddr>, UnsafeMutablePointer<socklen_t>) throws -> Void) throws {
//
//        // `sockaddr_storage` is an abstract type that provides storage large enough for any concrete socket address struct:
//        var addressStorage = 333
//        var addressStorageLength = socklen_t(MemoryLayout<sockaddr_storage>.size)
//        var tmp = withUnsafeMutablePointer(to: &addressStorage) {
//            let k = $0.withMemoryRebound(to: sockaddr.self, capacity: MemoryLayout<sockaddr>.size) { $0.pointee }
//            return try! addressProvider(k, &addressStorageLength)
//        }
//        
//        
////        try withUnsafeMutablePointer(&addressStorage, &addressStorageLength) {
////            try addressProvider(UnsafeMutablePointer<sockaddr>($0), $1)
////        }
////
//
//        switch Int32(addressStorage.ss_family) {
//        case AF_INET:
//            assert(socklen_t(addressStorage.ss_len) == SocketAddress.lengthOfVersion4)
//            self = withUnsafePointer(to: &tmp) { .version4(address: UnsafePointer<sockaddr_in>($0).pointee) }
//
//        case AF_INET6:
//            assert(socklen_t(addressStorage.ss_len) == SocketAddress.lengthOfVersion6)
//            self = withUnsafePointer(to: &tmp) { .version6(address: UnsafePointer<sockaddr_in6>($0).pointee) }
//
//        default:
//            throw Socket.Error.noAddressAvailable
//        }
//    }

    /// Creates an instance by inspecting the given `addrinfo`'s protocol family and socket address.
    ///
    /// - Important: The given `addrinfo` must contain either an IPv4 or IPv6 address.
    init(addrInfo: addrinfo) {
        switch addrInfo.ai_family {
        case AF_INET:
            assert(addrInfo.ai_addrlen == SocketAddress.lengthOfVersion4)
            
            self = .version4(address: addrInfo.ai_addr.withMemoryRebound(to: sockaddr_in.self, capacity: MemoryLayout<sockaddr_in>.size) { $0.pointee })

        case AF_INET6:
            assert(addrInfo.ai_addrlen == SocketAddress.lengthOfVersion6)
            self = .version6(address: addrInfo.ai_addr.withMemoryRebound(to: sockaddr_in6.self, capacity: MemoryLayout<sockaddr_in6>.size) { $0.pointee })

        default:
            fatalError("Unknown address size")
        }
    }

    /// Creates an instance for a given IPv4 socket address.
    init(address: sockaddr_in) {
        self = .version4(address: address)
    }

    /// Creates an instance for a given IPv6 socket address.
    init(address: sockaddr_in6) {
        self = .version6(address: address)
    }

    /// Makes a copy of `address` and calls the given closure with an `UnsafePointer<sockaddr>` to that.
    func withSockAddrPointer<Result>( _ body: (UnsafePointer<sockaddr>, socklen_t) throws -> Result) rethrows -> Result {

        func castAndCall<T>(_ address: T, _ body: (UnsafePointer<sockaddr>, socklen_t) throws -> Result) rethrows -> Result {
            var localAddress = address // We need a `var` here for the `&`.
            return try withUnsafePointer(to: &localAddress) {
                let buf = $0.withMemoryRebound(to: sockaddr.self, capacity: MemoryLayout<sockaddr>.size, {$0})
                return try body(buf, socklen_t(MemoryLayout<T>.size))
            }
        }

        switch self {
        case .version4(let address):
            return try castAndCall(address, body)

        case .version6(let address):
            return try castAndCall(address, body)
        }
    }

    /// Returns the host and port as returned by `getnameinfo()`.
    func nameInfo() throws -> (host: String, port: String) {
        var hostBuffer = [CChar](repeating: 0, count: 256)
        var portBuffer = [CChar](repeating: 0, count: 256)

        let result = withSockAddrPointer { sockAddr, length in
            Darwin.getnameinfo(sockAddr, length, &hostBuffer, socklen_t(hostBuffer.count), &portBuffer, socklen_t(portBuffer.count), 0)
        }

        guard result != -1 else {
            throw Socket.Error.getNameInfoFailed(code: errno)
        }

        guard let host = String(validatingUTF8: hostBuffer) else {
            throw Socket.Error.getNameInfoInvalidName
        }

        guard let port = String(validatingUTF8: portBuffer) else {
            throw Socket.Error.getNameInfoInvalidName
        }

        return (host, port)
    }

    #if false // Doesn't work yet.
    var displayName: String {
        func createDisplayName(address:UnsafePointer<Void>, family: Int32, maxLength: Int32) -> String {
            let pointer = UnsafeMutablePointer<CChar>.alloc(Int(maxLength))
            guard inet_ntop(family, address, pointer, socklen_t(maxLength)) != nil else {
                fatalError("Error converting IP address to displayName")
            }
            guard let displayName = String.fromCString(pointer) else {
                fatalError("Error converting IP address to displayName")
            }
            return displayName
        }

        switch self {
        case .Version4(var address):
            return createDisplayName(address: &address, family: AF_INET, maxLength: INET_ADDRSTRLEN)

        case .Version6(var address):
            return createDisplayName(address: &address, family: AF_INET6, maxLength: INET6_ADDRSTRLEN)
        }
    }
    #endif

}
