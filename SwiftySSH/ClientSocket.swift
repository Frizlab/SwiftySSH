//
//  ClientSocket.swift
//  SwiftySSH
//
//  Created by Solomenchuk, Vlad on 7/11/16.
//  Copyright © 2016 Vladimir Solomenchuk. All rights reserved.
//

import Foundation

struct BasicClientSocket: ClientSocketType {
    let socket: Socket
    let address: SocketAddress
}
