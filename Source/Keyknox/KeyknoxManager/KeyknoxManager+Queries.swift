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

import Foundation
import VirgilCrypto

// MARK: - Queries
extension KeyknoxManager {
    /// Pushes value
    ///
    /// - Parameters:
    ///   - params: Push params
    ///   - data: data to push
    ///   - previousHash: Previous hash
    ///   - publicKeys: public keys to encrypt
    ///   - privateKey: private key to sign
    /// - Returns: GenericOperation<DecryptedKeyknoxValue>
    open func pushValue(params: KeyknoxPushParams? = nil,
                        data: Data,
                        previousHash: Data?,
                        publicKeys: [VirgilPublicKey],
                        privateKeyWrapper: PrivateKeyWrapper) -> GenericOperation<DecryptedKeyknoxValue> {
        return CallbackOperation { _, completion in
            self.queue.async {
                do {
                    let privateKey = try privateKeyWrapper.getPrivateKey()

                    let encryptedData = try self.keyknoxCrypto.encrypt(data: data,
                                                                       privateKey: privateKey,
                                                                       publicKeys: publicKeys)
                    let keyknoxValue = try self.keyknoxClient.pushValue(params: params,
                                                                        meta: encryptedData.0,
                                                                        value: encryptedData.1,
                                                                        previousHash: previousHash)
                    let decryptedData = try self.keyknoxCrypto.decrypt(encryptedKeyknoxValue: keyknoxValue,
                                                                       privateKey: privateKey,
                                                                       publicKeys: publicKeys)

                    completion(decryptedData, nil)
                }
                catch {
                    completion(nil, error)
                }
            }
        }
    }

    /// Pulls value
    ///
    /// - Parameters:
    ///   - params: Pull params
    ///   - publicKeys: public keys to verify signature
    ///   - privateKey: private key to decrypt
    /// - Returns: GenericOperation<DecryptedKeyknoxValue>
    open func pullValue(params: KeyknoxPullParams? = nil,
                        publicKeys: [VirgilPublicKey],
                        privateKeyWrapper: PrivateKeyWrapper) -> GenericOperation<DecryptedKeyknoxValue> {
        return CallbackOperation { _, completion in
            self.queue.async {
                do {
                    let privateKey = try privateKeyWrapper.getPrivateKey()

                    let keyknoxValue = try self.keyknoxClient.pullValue(params: params)
                    let decryptedData = try self.keyknoxCrypto.decrypt(encryptedKeyknoxValue: keyknoxValue,
                                                                       privateKey: privateKey,
                                                                       publicKeys: publicKeys)

                    completion(decryptedData, nil)
                }
                catch {
                    completion(nil, error)
                }
            }
        }
    }

    /// Returns set of keys
    ///
    /// - Parameter params: Get keys params
    /// - Returns: GenericOperation<Set<String>>
    open func getKeys(params: KeyknoxGetKeysParams) -> GenericOperation<Set<String>> {
        return CallbackOperation { _, completion in
            self.queue.async {
                do {
                    let keys = try self.keyknoxClient.getKeys(params: params)

                    completion(keys, nil)
                }
                catch {
                    completion(nil, error)
                }
            }
        }
    }

    /// Resets Keyknox value (makes it empty)
    ///
    /// - Parameter params: reset params
    /// - Returns: GenericOperation<DecryptedKeyknoxValue>
    open func resetValue(params: KeyknoxResetParams? = nil) -> GenericOperation<DecryptedKeyknoxValue> {
        return CallbackOperation { _, completion in
            self.queue.async {
                do {
                    let resetValueResult = try self.keyknoxClient.resetValue(params: params)
                    completion(resetValueResult, nil)
                }
                catch {
                    completion(nil, error)
                }
            }
        }
    }

    /// Deletes recipient from list of shared
    ///
    /// - Parameter params: Delete recipient params
    /// - Returns: GenericOperation<DecryptedKeyknoxValue>
    open func deleteRecipient(params: KeyknoxDeleteRecipientParams) -> GenericOperation<DecryptedKeyknoxValue> {
        return CallbackOperation { _, completion in
            self.queue.async {
                do {
                    let keyknoxValue = try self.keyknoxClient.deleteRecipient(params: params)

                    completion(keyknoxValue, nil)
                }
                catch {
                    completion(nil, error)
                }
            }
        }
    }
}
