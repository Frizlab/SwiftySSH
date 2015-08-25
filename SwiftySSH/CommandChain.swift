//
//  Command.swift
//  SwiftySSH
//
//  Created by Solomenchuk, Vlad on 8/21/15.
//  Copyright © 2015 Vladimir Solomenchuk. All rights reserved.
//

import Foundation

//execute all on value set
//execute new on append if value set
class CommandChain<T> {
    typealias CommandType = (T) -> Void
    private var commands: [(id: String, command: CommandType)]! = []
    private var valueSet: Bool = false
    private var _value: T?
    
    init () {
    }
    
    func append(command: (T) -> Void) {
        if valueSet {
            command(value)
        }
        
        commands.append((id: NSUUID().UUIDString, command: command))
    }
    
    func remove(id: String) {
        commands = commands.filter({ (tuple) -> Bool in
            return tuple.id == id
        })
    }
    
    func reset () {
        commands = []
        valueSet = false
        _value = nil
    }
    
    var value: T {
        set (value) {
            _value = value
            valueSet = true
            execAll(value)
        }
        
        get {
            return _value!
        }
    }
    
    private func execAll(arg: T) {
        for tuple in commands {
            tuple.command(arg)
        }
    }
}