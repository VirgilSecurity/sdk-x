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

import VirgilCrypto

/// Class for saving data to the filesystem
/// - Note: This class is NOT thread-safe
/// - Tag: FileSystem
@objc(VSSFileSystem) open class FileSystem: NSObject {
    private let fileManager = FileManager()

    /// Prefix
    @objc public let prefix: String

    /// User identifier (identity)
    @objc public let userIdentifier: String

    /// Path components
    @objc public let pathComponents: [String]

    /// Encryption credentials
    @objc public let credentials: FileSystemCredentials?

    /// Init
    ///
    /// - Parameters:
    ///   - prefix: prefix
    ///   - userIdentifier: user identifier
    ///   - pathComponents: path components
    ///   - credentials: encryption credentials
    @objc public init(prefix: String,
                      userIdentifier: String,
                      pathComponents: [String],
                      credentials: FileSystemCredentials? = nil) {
        self.prefix = prefix
        self.userIdentifier = userIdentifier
        self.pathComponents = pathComponents
        self.credentials = credentials

        super.init()
    }

    private func createSuppDir() throws -> URL {
        var dirUrl = try self.fileManager.url(for: .applicationSupportDirectory,
                                              in: .userDomainMask,
                                              appropriateFor: nil,
                                              create: true)

        dirUrl.appendPathComponent(self.prefix)
        dirUrl.appendPathComponent(self.userIdentifier)

        do {
            try self.fileManager.createDirectory(at: dirUrl, withIntermediateDirectories: true, attributes: nil)
            Log.debug("Created \(dirUrl.absoluteString) folder")

            var values = URLResourceValues()
            values.isExcludedFromBackup = true

            try dirUrl.setResourceValues(values)
        }
        catch {
            Log.error("Error creating \(dirUrl.absoluteString) folder")
            throw error
        }

        return dirUrl
    }

    private func writeFile(url: URL, data: Data) throws {
    #if os(OSX)
        let options: Data.WritingOptions = [.atomic]
    #else
        let options: Data.WritingOptions = [
            .completeFileProtection /* Is accessing in background needed? */,
            .atomic
        ]
    #endif

        let dataToWrite = try self.encrypt(data: data)

        try dataToWrite.write(to: url, options: options)
    }

    private func readFile(url: URL) throws -> Data {
        let data = (try? Data(contentsOf: url)) ?? Data()

        return try self.decrypt(data: data)
    }

    private func encrypt(data: Data) throws -> Data {
        guard !data.isEmpty else {
            return data
        }

        guard let credentials = self.credentials else {
            return data
        }

        let keyPair = try credentials.privateKeyWrap.getKeyPair()

        return try credentials.crypto.authEncrypt(data,
                                                  with: keyPair.privateKey,
                                                  for: [keyPair.publicKey])
    }

    private func decrypt(data: Data) throws -> Data {
        guard !data.isEmpty else {
            return data
        }

        guard let credentials = self.credentials else {
            return data
        }

        let keyPair = try credentials.privateKeyWrap.getKeyPair()

        return try credentials.crypto.authDecrypt(data,
                                                  with: keyPair.privateKey,
                                                  usingOneOf: [keyPair.publicKey],
                                                  allowNotEncryptedSignature: true)
    }

    private func getFileNames(url: URL) throws -> [String] {
        let fileURLs = try self.fileManager.contentsOfDirectory(at: url,
                                                                includingPropertiesForKeys: nil,
                                                                options: .skipsHiddenFiles)

        return fileURLs.map { $0.lastPathComponent }
    }

    private func getFullUrl(name: String?, subdir: String?) throws -> URL {
        var url = try self.createSuppDir()

        self.pathComponents.forEach {
            url.appendPathComponent($0)
        }

        if let subdir = subdir {
            url.appendPathComponent(subdir)
        }

        try self.fileManager.createDirectory(at: url, withIntermediateDirectories: true, attributes: nil)

        if let name = name {
            url.appendPathComponent(name)
        }

        return url
    }
}

// MARK: - Public API
public extension FileSystem {
    /// Write data
    ///
    /// - Parameters:
    ///   - data: data to write
    ///   - name: file name
    ///   - subdir: subdirectory
    /// - Throws: Rethrows from `FileManager`
    @objc func write(data: Data, name: String, subdir: String? = nil) throws {
        let url = try self.getFullUrl(name: name, subdir: subdir)

        try self.writeFile(url: url, data: data)
    }

    /// Read data
    ///
    /// - Parameters:
    ///   - name: file name
    ///   - subdir: subdirectory
    /// - Returns: Data
    /// - Throws: Rethrows from `FileManager`
    @objc func read(name: String, subdir: String? = nil) throws -> Data {
        let url = try self.getFullUrl(name: name, subdir: subdir)

        return try self.readFile(url: url)
    }

    /// Returns file names in given subdirectoty
    ///
    /// - Parameter subdir: subdirectory
    /// - Returns: File names
    /// - Throws: Rethrows from `FileManager`
    @objc func getFileNames(subdir: String? = nil) throws -> [String] {
        let url = try self.getFullUrl(name: nil, subdir: subdir)

        return try self.getFileNames(url: url)
    }

    /// Delete data
    ///
    /// - Parameters:
    ///   - name: file name
    ///   - subdir: subdirectory
    /// - Throws: Rethrows from `FileManager`
    @objc func delete(name: String, subdir: String? = nil) throws {
        let url = try self.getFullUrl(name: name, subdir: subdir)

        try self.fileManager.removeItem(at: url)
    }

    /// Delete directory
    ///
    /// - Parameter subdir: subdirectory
    /// - Throws: Rethrows from `FileManager`
    @objc func delete(subdir: String? = nil) throws {
        let url = try self.getFullUrl(name: nil, subdir: subdir)

        try self.fileManager.removeItem(at: url)
    }
}
