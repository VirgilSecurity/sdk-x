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
import UIKit

/// Class for accessing biometrically secured private keys, with proper caching
@objc(VSSProtectedKey) public class ProtectedKey: NSObject {
    /// Key name
    @objc public let keyName: String

    /// Access time during which key is cached in RAM. If nil, key won't be cleaned from RAM using timer. Default - nil
    public let accessTime: TimeInterval?

    /// KeychainStorage
    @objc public let keychainStorage: KeychainStorage

    /// Cleans private key from RAM on entering background. Default - false
    @objc public let cleanOnEnterBackground: Bool

    /// Requests private key on entering foreground. Default - false
    @objc public let requestOnEnterForeground: Bool

    /// Error callback function type
    public typealias ErrorCallback = (Error) -> Void

    /// Error callback for errors during entering foreground. Default - nil
    public let enterForegroundErrorCallback: ErrorCallback?

    /// Init
    /// - Parameters:
    ///   - keyName: key name
    ///   - options: ProtectedKeyOptions
    @objc public init(keyName: String, options: ProtectedKeyOptions? = nil) throws {

        let keyOptions: ProtectedKeyOptions

        if let options = options {
            keyOptions = options
        }
        else {
            keyOptions = try ProtectedKeyOptions.makeOptions()
        }

        self.keyName = keyName
        self.accessTime = keyOptions.accessTime
        self.cleanOnEnterBackground = keyOptions.cleanOnEnterBackground
        self.requestOnEnterForeground = keyOptions.requestOnEnterForeground
        self.enterForegroundErrorCallback = keyOptions.enterForegroundErrorCallback
        self.keychainStorage = keyOptions.keychainStorage

        super.init()

        if self.cleanOnEnterBackground {
            NotificationCenter.default.addObserver(self,
                                                   selector: #selector(didEnterBackgroundHandler),
                                                   name: UIApplication.didEnterBackgroundNotification,
                                                   object: nil)
        }

        if self.requestOnEnterForeground {
            NotificationCenter.default.addObserver(self,
                                                   selector: #selector(willEnterForegroundHandler),
                                                   name: UIApplication.willEnterForegroundNotification,
                                                   object: nil)
        }
    }

    private var timer: Timer?
    private var keychainEntry: KeychainEntry?
    private let queue = DispatchQueue(label: "VSSProtectedKeyQueue")

    @objc private func didEnterBackgroundHandler() {
        if self.cleanOnEnterBackground {
            self.queue.sync {
                self.deleteKey()
            }
        }
    }

    private var uiTimer: Timer?

    @objc private func willEnterForegroundHandler() {
        if self.requestOnEnterForeground && self.keychainEntry == nil {
            self.queue.sync {
                if self.uiTimer != nil {
                    self.uiTimer?.suspend()
                    self.uiTimer = nil
                }

                let uiTimer = Timer(timerType: .oneTime(0.5)) { [weak self] in
                    self?.queue.sync {
                        do {
                            _ = try self?.getKeychainEntryInternal(runInQueue: false)
                        }
                        catch {
                            self?.enterForegroundErrorCallback?(error)
                        }

                        self?.uiTimer = nil
                    }
                }

                self.uiTimer = uiTimer
                uiTimer.resume()
            }
        }
    }

    private func getKeychainEntryInternal(runInQueue: Bool) throws -> KeychainEntry {
        let closure = { () -> KeychainEntry in
            if let keychainEntry = self.keychainEntry {
                return keychainEntry
            }

            let options = KeychainQueryOptions()
            options.biometricallyProtected = true

            let newKeychainEntry = try self.keychainStorage.retrieveEntry(withName: self.keyName, queryOptions: options)

            self.updateKeychainEntry(keychainEntry: newKeychainEntry)

            return newKeychainEntry
        }

        if runInQueue {
            return try self.queue.sync {
                try closure()
            }
        }
        else {
            return try closure()
        }
    }

    /// Returns keychain entry
    @objc public func getKeychainEntry() throws -> KeychainEntry {
        return try self.getKeychainEntryInternal(runInQueue: true)
    }

    private func deleteKey() {
        self.timer = nil
        self.keychainEntry = nil
    }

    private func updateKeychainEntry(keychainEntry: KeychainEntry) {
        self.keychainEntry = keychainEntry

        if let accessTime = self.accessTime {
            let timer = Timer(timerType: .oneTime(accessTime)) { [weak self] in
                self?.deleteKey()
            }

            self.timer = timer
            timer.resume()
        }
    }

    deinit {
        NotificationCenter.default.removeObserver(self)
    }
}
