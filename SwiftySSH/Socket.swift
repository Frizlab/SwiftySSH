//
//  Socket.swift
//  SocketWrapper
//
//  Created by Christian Ludl on 2016-02-09.
//  Copyright © 2016 Objective Development. All rights reserved.
//

import Darwin

/// A low-level wrapper around a POSIX socket, i.e. a file descriptor typed as `Int32`.
///
/// Provides wrapper methods for calling various socket functions that `throw` a `Socket.Error`
/// instead of returning `-1` and setting the global `errno`.
struct Socket {

    typealias Byte = UInt8

    /// The underlying file descriptor.
    let fileDescriptor: Int32

    /// Initializer for when a file descriptor exists already.
    init(fileDescriptor: Int32) {
        self.fileDescriptor = fileDescriptor
    }

    /// Initializer for creating a new file descriptor using `Darwin.socket()` using the `addrinfo`.
    init(addrInfo: addrinfo) throws {
        let fileDescriptor = Darwin.socket(addrInfo.ai_family, addrInfo.ai_socktype, addrInfo.ai_protocol)
        guard fileDescriptor != -1 else {
            throw Error.createFailed(code: errno)
        }
        self.init(fileDescriptor: fileDescriptor)
    }

}


/// Socket errors.
extension Socket {

    /// Most of these errors are thrown whenever a low level socket function returns `-1`.
    /// Their associated error code then provides detailed information on the error.
    enum Error: Swift.Error, CustomStringConvertible {
        case bindFailed(code: errno_t)
        case closeFailed(code: errno_t)
        case connectFailed(code: errno_t)
        case connectionClosed
        case createFailed(code: errno_t)
        case getAddrInfoFailed(code: Int32)
        case getNameInfoFailed(code: errno_t)
        case getNameInfoInvalidName
        case listenFailed(code: errno_t)
        case noAddressAvailable
        case noDataAvailable
        case receivedInvalidData
        case receiveFailed(code: errno_t)
        case sendFailed(code: errno_t)
        case acceptFailed(code: errno_t)

        var description: String {
            func errorString(_ code: errno_t) -> String {
                return String(validatingUTF8: strerror(code))!
            }

            switch self {
            case .acceptFailed(let code):
                return "accept() failed: " + errorString(code)

            case .bindFailed(let code):
                return "bind() failed: " + errorString(code)

            case .closeFailed(let code):
                return "close() failed: " + errorString(code)

            case .connectionClosed:
                return "Connection closed."

            case .connectFailed(let code):
                return "connect() failed: " + errorString(code)

            case .createFailed(let code):
                return "socket() failed: " + errorString(code)

            case .getAddrInfoFailed(let code):
                return "getaddrinfo() failed: " + String(validatingUTF8: gai_strerror(code))!

            case .getNameInfoFailed(let code):
                return "getnameinfo() failed: " + errorString(code)

            case .getNameInfoInvalidName:
                return "getnameinfo() returned invalid name."

            case .listenFailed(let code):
                return "listen() failed: " + errorString(code)

            case .noAddressAvailable:
                return "getaddrinfo() returned no address."

            case .noDataAvailable:
                return "No data available"

            case .sendFailed(let code):
                return "send() failed: " + errorString(code)

            case .receivedInvalidData:
                return "Received invalid data"
                
            case .receiveFailed(let code):
                return "recv() failed: " + errorString(code)
            }
        }
    }

}


/// Sending data.
extension Socket {

    /// Sends the data in the given `buffer`.
    ///
    /// - SeeAlso: `send(2)`
    func send(_ buffer: UnsafeBufferPointer<Byte>, flags: Int32 = 0) throws -> Int {
        let result = Darwin.send(fileDescriptor, buffer.baseAddress, buffer.count, flags)
        guard result != -1 else {
            throw Error.sendFailed(code: errno)
        }
        return result
    }

    /// Sends the chunk of data defined by `pointer` and `count`.
    func send(_ pointer: UnsafePointer<Byte>, count: Int, flags: Int32 = 0) throws -> Int {
        return try send(UnsafeBufferPointer(start: pointer, count: count), flags: flags)
    }

}


// Receiving data.
extension Socket {

    /// Receives data into `buffer`.
    ///
    /// - Parameter buffer: A previously allocated buffer that this method writes into.
    /// - Parameter flags: Flags that are passed to `Darwin.recv()`.
    /// - Parameter blocking: If no data is available and...
    ///   - `blocking` is `true`: blocks until any data is available.
    ///   - `blocking` is `false`: throws `Socket.Error.NoDataAvailable`.
    ///
    /// - SeeAlso: `recv(2)`
    func receive(_ buffer: UnsafeMutableBufferPointer<Byte>, flags: Int32 = 0, blocking: Bool = false) throws -> Int {
        self[fileOption: O_NONBLOCK] = !blocking
        let bytesReceived = Darwin.recv(fileDescriptor, buffer.baseAddress, buffer.count, flags)
        guard bytesReceived != -1 else {
            switch errno {
            case EAGAIN:
                throw Error.noDataAvailable

            case let error:
                throw Error.receiveFailed(code: error)
            }
        }
        guard bytesReceived != 0 else {
            throw Error.connectionClosed
        }
        return bytesReceived
    }

    /// Receives a chunk of data to `pointer` with a maximum of `count`.
    func receive(_ pointer: UnsafeMutablePointer<Byte>, count: Int, flags: Int32 = 0, blocking: Bool = false) throws -> Int {
        return try receive(UnsafeMutableBufferPointer(start: pointer, count: count), flags: flags, blocking: blocking)
    }

}


/// Closing the socket.
extension Socket {

    /// Closes the socket.
    ///
    /// - SeeAlso: `close(2)`
    func close() throws {
        guard Darwin.close(fileDescriptor) != -1 else {
            throw Error.closeFailed(code: errno)
        }
    }
    
}


/// Server socket methods.
extension Socket {

    /// Binds the given address to the server socket.
    ///
    /// - SeeAlso: `bind(2)`
    func bind(_ address: UnsafePointer<sockaddr>, length: socklen_t) throws {
        guard Darwin.bind(fileDescriptor, address, length) != -1 else {
            throw Error.bindFailed(code: errno)
        }
    }

    /// Starts listening for client connections on the server socket with type `SOCK_STREAM` (i.e. TCP).
    ///
    /// - SeeAlso: `listen(2)`
    func listen(_ backlog: Int32) throws {
        guard Darwin.listen(fileDescriptor, backlog) != -1 else {
            throw Error.listenFailed(code: errno)
        }
    }

    /// Accept a connection on the server socket and return. If no new client has connected and...
    ///  - `blocking` is `true`: blocks until a client connects.
    ///  - `blocking` is `false`: throws `Socket.Error.NoDataAvailable`.
    ///
    /// - SeeAlso: `accept(2)`
//    func accept(_ blocking: Bool = false) throws -> (Socket, SocketAddress) {
//        self[fileOption: O_NONBLOCK] = !blocking
//
//        var clientFileDescriptor: Int32 = 0
//        let socketAddress = try SocketAddress() { sockaddr, length in
//            clientFileDescriptor = Darwin.accept(self.fileDescriptor, sockaddr, length)
//            guard clientFileDescriptor != -1 else {
//                switch errno {
//                case EAGAIN:
//                    throw Error.noDataAvailable
//
//                case let error:
//                    throw Error.acceptFailed(code: error)
//                }
//            }
//        }
//        return (Socket(fileDescriptor: clientFileDescriptor), socketAddress)
//    }

}


/// Client socket methods.
extension Socket {

    /// Connects the socket to a peer.
    ///
    /// - SeeAlso: `connect(2)`
    func connect(_ address: UnsafePointer<sockaddr>, length: socklen_t) throws {
        guard Darwin.connect(fileDescriptor, address, length) == 0 else {
            throw Error.connectFailed(code: errno)
        }
    }

}

/// Subscripts.
extension Socket {

    /// A wrapper around `getsockopt()` and `setsockopt` with a level of `SOL_SOCKET`.
    ///
    /// - SeeAlso: `getsockopt(2)`
    ///
    /// - This should probably be a method that can throw.
    subscript(socketOption option: Int32) -> Int32 {

        get {
            var value: Int32 = 0
            var valueLength = socklen_t(MemoryLayout<Int32>.size)

            guard getsockopt(fileDescriptor, SOL_SOCKET, option, &value, &valueLength) != -1 else {
                let errorNumber = errno
                print("getsockopt() failed for option \(option). \(errorNumber) \(strerror(errorNumber))")
                return 0
            }

            return value
        }

        nonmutating set {
            var value = newValue

            guard setsockopt(fileDescriptor, SOL_SOCKET, option, &value, socklen_t(MemoryLayout<Int32>.size)) != -1 else {
                let errorNumber = errno
                print("setsockopt() failed for option \(option), value \(value). \(errorNumber) \(strerror(errorNumber))")
                return
            }
        }
        
    }

    /// A wrapper around `fcntl()` for the  `F_GETFL` and `F_SETFL` commands.
    ///
    /// - SeeAlso: `fcntl(2)`
    ///
    /// - This should probably be a method that can throw.
    subscript(fileOption option: Int32) -> Bool {

        get {
            let allFlags = fcntl(fileDescriptor, F_GETFL)
            guard allFlags != -1 else {
                let errorNumber = errno
                print("fcntl() failed for F_GETFL, option: \(option). \(errorNumber) \(strerror(errorNumber))")
                return false
            }

            return (allFlags & option) != 0
        }

        nonmutating set {
            var flags = fcntl(fileDescriptor, F_GETFL)
            guard flags != -1 else {
                let errorNumber = errno
                print("fcntl() failed for F_GETFL, option: \(option). \(errorNumber) \(strerror(errorNumber))")
                return
            }

            if newValue {
                flags |= option
            } else {
                flags &= ~option
            }

            guard fcntl(fileDescriptor, F_SETFL, flags) != -1 else {
                let errorNumber = errno
                print("fcntl() failed for F_SETFL, option: \(option). \(errorNumber) \(strerror(errorNumber))")
                return
            }
        }

    }

}
