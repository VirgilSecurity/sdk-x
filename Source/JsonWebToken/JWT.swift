//
//  JWT.swift
//  VirgilSDK
//
//  Created by Eugen Pivovarov on 1/9/18.
//  Copyright © 2018 VirgilSecurity. All rights reserved.
//

import Foundation

/// Class implementing `AccessToken` in terms of JWT
@objc(VSSJwt) public class Jwt: NSObject, AccessToken {
    @objc public let headerContent: JwtHeaderContent
    @objc public let bodyContent: JwtBodyContent
    @objc public private(set) var string: String
    @objc public private(set) var signatureContent: Data?

    /// Declares error types and codes
    ///
    /// - tokenCorrupted: token is corrupted and cannot be used
    @objc public enum JwtError: Int, Error {
        case tokenCorrupted = 1
    }

    /// Initializes `Jwt` with provided header, body and signature content
    ///
    /// - Parameters:
    ///   - headerContent: header of `Jwt`
    ///   - bodyContent: body of `Jwt`
    ///   - signatureContent: Data with signature content (optional)
    @objc public init?(headerContent: JwtHeaderContent, bodyContent: JwtBodyContent, signatureContent: Data? = nil) {
        self.headerContent = headerContent
        self.bodyContent = bodyContent
        self.signatureContent = signatureContent

        guard let headerBase64Url = try? self.headerContent.getBase64Url(),
              let bodyBase64Url = try? self.bodyContent.getBase64Url() else { return nil }

        var result = headerBase64Url + "." + bodyBase64Url

        if let signatureContent = signatureContent {
            result += "." + signatureContent.base64UrlEncodedString()
        }
        self.string = result

        super.init()
    }

    /// Initializes `Jwt` from its string representation
    ///
    /// - Parameter jwtToken: must be equal to base64UrlEncode(JWT Header) + "." + base64UrlEncode(JWT Body) + "." + base64UrlEncode(Jwt Signature)
    @objc public init?(jwtToken: String) {
        let array = jwtToken.components(separatedBy: ".")

        guard array.count >= 2 else {
            return nil
        }
        let headerBase64Url = array[0]
        let bodyBase64Url = array[1]

        guard let headerContent = JwtHeaderContent(base64Url: headerBase64Url),
              let bodyContent = JwtBodyContent(base64Url: bodyBase64Url) else { return nil }

        var signatureContent: Data? = nil
        if array.count == 3 {
            let signatureBase64Url = array[2]
            signatureContent = Data(base64UrlEncoded: signatureBase64Url)
        }
        self.headerContent = headerContent
        self.bodyContent = bodyContent
        self.signatureContent = signatureContent
        self.string = jwtToken

        super.init()
    }

    public func snapshotWithoutSignatures() throws -> Data {
        let headerBase64Url = try self.headerContent.getBase64Url()
        let bodyBase64Url = try self.bodyContent.getBase64Url()

        let string: String = headerBase64Url + "." + bodyBase64Url

        guard let data = string.data(using: .utf8) else {
            throw JwtError.tokenCorrupted
        }

        return data
    }

    @objc public func stringRepresentation() -> String {
        return self.string
    }

    @objc public func identity() -> String {
        return self.bodyContent.identity
    }

    @objc public func isExpired() -> Bool {
        return Int(Date().timeIntervalSince1970) >= self.bodyContent.expiresAt
    }

    public func setSignatureContent(_ signatureContent: Data) throws {
        self.signatureContent = signatureContent
        let headerBase64Url = try self.headerContent.getBase64Url()
        let bodyBase64Url = try self.bodyContent.getBase64Url()

        self.string = headerBase64Url + "." + bodyBase64Url + "." + signatureContent.base64UrlEncodedString()
    }
}
