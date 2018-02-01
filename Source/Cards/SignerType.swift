//
//  SignerType.swift
//  VirgilSDK
//
//  Created by Oleksandr Deundiak on 9/15/17.
//  Copyright © 2017 VirgilSecurity. All rights reserved.
//

import Foundation

@objc(VSSSignerType) public enum SignerType: Int, Codable {
    case `self`
    case virgil
    case app
    
    private enum CodingKeys: String, CodingKey {
        case `self`      = "self"
        case virgil      = "virgil"
        case app       = "app"
    }
    
    enum SignerTypeInternal: String {
        case `self`      = "self"
        case virgil      = "virgil"
        case app       = "app"
        
        init(internal: SignerType) {
            switch `internal` {
            case .self: self = .self
            case .virgil: self = .virgil
            case .app: self = .app
            }
        }
        
        var external: SignerType {
            switch self {
            case .self: return .self
            case .virgil: return .virgil
            case .app: return .app
            }
        }
    }
    
    private var `internal`: SignerTypeInternal { return SignerTypeInternal(internal: self) }
    
    init?(from string: String) {
        guard let `internal` = SignerTypeInternal(rawValue: string) else {
            return nil
        }
        
        self = `internal`.external
    }
    
    func toString() -> String {
        return self.internal.rawValue
    }
}

