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

// MARK: - Obj-C extension
extension KeyknoxManager {
    /// Pushes value
    ///
    /// - Parameters:
    ///   - params: Push params
    ///   - data: data to push
    ///   - previousHash: Previous hash
    ///   - publicKeys: public keys to encrypt
    ///   - privateKey: private key to sign
    ///   - completion: completion handler
    @objc open func pushValue(params: KeyknoxPushParams? = nil,
                              data: Data,
                              previousHash: Data?,
                              publicKeys: [VirgilPublicKey],
                              privateKey: VirgilPrivateKey,
                              completion: @escaping (DecryptedKeyknoxValue?, Error?) -> Void) {
        self.pushValue(params: params,
                       data: data,
                       previousHash: previousHash,
                       publicKeys: publicKeys,
                       privateKeyWrapper: PrivateKeyWrapper(privateKey: privateKey, crypto: self.crypto))
            .start(completion: completion)
    }

    /// Pulls value
    ///
    /// - Parameters:
    ///   - params: Pull params
    ///   - publicKeys: public keys to verify signature
    ///   - privateKey: private key to decrypt
    ///   - completion: completion handler
    @objc open func pullValue(params: KeyknoxPullParams? = nil,
                              publicKeys: [VirgilPublicKey],
                              privateKey: VirgilPrivateKey,
                              completion: @escaping (DecryptedKeyknoxValue?, Error?) -> Void) {
        self.pullValue(params: params,
                       publicKeys: publicKeys,
                       privateKeyWrapper: PrivateKeyWrapper(privateKey: privateKey, crypto: self.crypto))
            .start(completion: completion)
    }

    /// Returns set of keys
    ///
    /// - Parameter params: Get keys params
    ///   - completion: completion handler
    @objc open func getKeys(params: KeyknoxGetKeysParams,
                            completion: @escaping (Set<String>?, Error?) -> Void) {
        self.getKeys(params: params).start(completion: completion)
    }

    /// Resets Keyknox value (makes it empty)
    ///
    ///   - params: Reset pararms
    ///   - completion: completion handler
    @objc open func resetValue(params: KeyknoxResetParams? = nil,
                               completion: @escaping(DecryptedKeyknoxValue?, Error?) -> Void) {
        self.resetValue(params: params).start(completion: completion)
    }

    /// Deletes recipient from list of shared
    ///
    /// - Parameters:
    ///   - params: Delete recipient params
    ///   - completion: completion handler
    @objc open func deleteRecipient(params: KeyknoxDeleteRecipientParams,
                                    completion: @escaping (DecryptedKeyknoxValue?, Error?) -> Void) {
        self.deleteRecipient(params: params).start(completion: completion)
    }
}
