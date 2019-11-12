//
// Copyright (C) 2015-2019 Virgil Security Inc.
//
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
//     (1) Redistributions of source code must retain the above copyright
//     notice, this list of conditions and the following disclaimer.
//
//     (2) Redistributions in binary form must reproduce the above copyright
//     notice, this list of conditions and the following disclaimer in
//     the documentation and/or other materials provided with the
//     distribution.
//
//     (3) Neither the name of the copyright holder nor the names of its
//     contributors may be used to endorse or promote products derived from
//     this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE AUTHOR ''AS IS'' AND ANY EXPRESS OR
// IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
// WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
// INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
// (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
// HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
// IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
// POSSIBILITY OF SUCH DAMAGE.
//
// Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>
//

import VirgilSDK
import VirgilCrypto

private class Config: NSObject, Decodable {
    let ServicePublicKey: String?
    let ApiPrivateKey: String
    let ApiKeyId: String
    let AppId: String
    let ServiceURL: String?
    let CardId: String
    let CardIdentity: String
}
    
@objc public class TestUtils: NSObject {
    
    @objc public let crypto: VirgilCrypto

    private let config: Config

    @objc public var cardId: String {
        return self.config.CardId
    }

    @objc public var cardIdentity: String {
        return self.config.CardIdentity
    }

    private let apiKey: VirgilPrivateKey
    private let servicePublicKey: VirgilPublicKey?
    private let serviceURL: URL?
    
    private init(config: Config) {
        self.config = config
        let crypto = try! VirgilCrypto()
        self.crypto = crypto
        
        self.apiKey = try! crypto.importPrivateKey(from: Data(base64UrlEncoded: self.config.ApiPrivateKey)!).privateKey

        self.servicePublicKey = config.ServicePublicKey == nil ?
            nil : try! crypto.importPublicKey(from: Data(base64UrlEncoded: config.ServicePublicKey!)!)

        self.serviceURL = config.ServiceURL == nil ? nil : URL(string: config.ServiceURL!)!
        
        super.init()
    }
    
    @objc public static func readFromBundle() -> TestUtils {
        let bundle = Bundle(for: self)
        let configFileUrl = bundle.url(forResource: "TestConfig", withExtension: "plist")!
        let data = try! Data(contentsOf: configFileUrl)
        
        return TestUtils(config: try! PropertyListDecoder().decode(Config.self, from: data))
    }

    @objc public func generateToken(withIdentity identity: String, ttl: TimeInterval) -> AccessToken  {
        let generator = try! JwtGenerator(apiKey: self.apiKey,
                                          apiPublicKeyIdentifier: self.config.ApiKeyId,
                                          crypto: self.crypto,
                                          appId: self.config.AppId,
                                          ttl: ttl)

        return try! generator.generateToken(identity: identity)
    }
    
    @objc public func getGeneratorJwtProvider(withIdentity identity: String) -> AccessTokenProvider {
        let generator = try! JwtGenerator(apiKey: self.apiKey,
                                          apiPublicKeyIdentifier: self.config.ApiKeyId,
                                          crypto: self.crypto,
                                          appId: self.config.AppId)
        
        return CachingJwtProvider(renewJwtCallback: { (_, completion) in
            do {
                completion(try generator.generateToken(identity: identity), nil)
            }
            catch {
                completion(nil, error)
            }
        })
    }
    
    @objc public func getRandomData() -> Data {
        return try! self.crypto.generateRandomData(ofSize: 1024)
    }

    @objc public func publishCard(identity: String?, previousCardId: String? = nil) throws -> Card {
        let keyPair = try self.crypto.generateKeyPair()
        let exportedPublicKey = try self.crypto.exportPublicKey(keyPair.publicKey)

        let identity = identity ?? UUID().uuidString

        let content = RawCardContent(identity: identity,
                                     publicKey: exportedPublicKey,
                                     previousCardId: previousCardId,
                                     createdAt: Date())
        let snapshot = try content.snapshot()

        let rawCard = RawSignedModel(contentSnapshot: snapshot)

        let token = self.generateToken(withIdentity: identity, ttl: 1000)

        let serviceUrl = URL(string: self.config.ServiceURL!)!

        let provider = ConstAccessTokenProvider(accessToken: token)

        let cardClient = CardClient(accessTokenProvider: provider,
                                    serviceUrl: serviceUrl,
                                    connection: nil,
                                    retryConfig: ExpBackoffRetry.Config())

        let signer = ModelSigner(crypto: self.crypto)

        try! signer.selfSign(model: rawCard, privateKey: keyPair.privateKey)

        let responseRawCard = try cardClient.publishCard(model: rawCard)
        let card = try CardManager.parseCard(from: responseRawCard, crypto: crypto)

        return card
    }

    @objc public func setupVerifier(whitelists: [Whitelist]) -> VirgilCardVerifier {
        let verfier: VirgilCardVerifier

        if let servicePublicKey = self.servicePublicKey {
            let creds = VerifierCredentials(signer: "virgil", publicKey: servicePublicKey)

            let whitelists = whitelists + [try! Whitelist(verifiersCredentials: [creds])]

            verfier = VirgilCardVerifier(crypto: self.crypto, whitelists: whitelists)!
            verfier.verifyVirgilSignature = false
        } else {
            verfier = VirgilCardVerifier(crypto: self.crypto, whitelists: whitelists)!
        }
        
        return verfier
    }
    
    @objc public func setupClient(withIdentity identity: String) -> CardClient {
        return self.setupClient(tokenProvider: self.getGeneratorJwtProvider(withIdentity: identity))
    }

    @objc public func setupClient(tokenProvider: AccessTokenProvider) -> CardClient {

        return CardClient(accessTokenProvider: tokenProvider,
                          serviceUrl: self.serviceURL ?? CardClient.defaultURL)
    }

    @objc public func setupKeyknoxClient(withIdentity identity: String) -> KeyknoxClient {

        return KeyknoxClient(accessTokenProvider: self.getGeneratorJwtProvider(withIdentity: identity),
                             serviceUrl: self.serviceURL ?? KeyknoxClient.defaultURL)
    }

    @objc public func setupKeyknoxManager(client: KeyknoxClient, crypto: VirgilCrypto) -> KeyknoxManager {
        return KeyknoxManager(keyknoxClient: client, crypto: crypto)
    }
}

// Comparisons
extension TestUtils {
    @objc public func isCardsEqual(card1: Card?, card2: Card?) -> Bool {
        if card1 == card2 {
            return true
        }

        guard let card1 = card1, let card2 = card2 else {
            return false
        }

        let selfSignature1 = card1.signatures.first { $0.signer == "self" }
        let selfSignature2 = card2.signatures.first { $0.signer == "self" }

        return card1.identifier == card2.identifier &&
            card1.identity == card2.identity &&
            card1.version == card2.version &&
            card1.isOutdated == card2.isOutdated &&
            card1.createdAt == card2.createdAt &&
            card1.previousCardId == card2.previousCardId &&
            self.isCardsEqual(card1: card1.previousCard, card2: card2.previousCard) &&
            self.isCardSignaturesEqual(signature1: selfSignature1, signature2: selfSignature2)
    }

    @objc public func isCardSignaturesEqual(signature1: CardSignature?, signature2: CardSignature?) -> Bool {
        if signature1 == signature2 {
            return true
        }

        guard let signature1 = signature1, let signature2 = signature2 else {
            return false
        }

        return signature1.signer == signature2.signer &&
            signature1.signature == signature2.signature &&
            signature1.snapshot == signature2.snapshot &&
            signature1.extraFields == signature2.extraFields
    }
}
