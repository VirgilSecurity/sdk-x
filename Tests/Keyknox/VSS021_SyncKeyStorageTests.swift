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

@testable import VirgilSDK
import XCTest
import VirgilCrypto

class VSS004_SyncKeyStorageTests: XCTestCase {
    private var syncKeyStorage: SyncKeyStorage!
    private var keychainStorageWrapper: KeychainStorageProtocol!
    private var cloudKeyStorage: CloudKeyStorage!
    private var keychainStorage: KeychainStorage!
    private var crypto: VirgilCrypto!
    
    override func setUp() {
        super.setUp()
        
        let utils = TestUtils.readFromBundle()
        self.crypto = utils.crypto

        let identity = NSUUID().uuidString
        let keyknoxClient = utils.setupKeyknoxClient(withIdentity: identity)
        
        let keyPair = try! crypto.generateKeyPair()

        let keyknoxManager = utils.setupKeyknoxManager(client: keyknoxClient, crypto: self.crypto)

        self.cloudKeyStorage = CloudKeyStorage(keyknoxManager: keyknoxManager,
                                               publicKeys: [keyPair.publicKey],
                                               privateKey: keyPair.privateKey)
        try! self.cloudKeyStorage.retrieveCloudEntries().startSync().get()

        let cloudKeyStorage = CloudKeyStorage(keyknoxManager: keyknoxManager,
                                              publicKeys: [keyPair.publicKey],
                                              privateKey: keyPair.privateKey)
        
    #if os(macOS)
        self.syncKeyStorage = SyncKeyStorage(identity: identity,
                                             keychainStorage: KeychainStorage(storageParams: try! KeychainStorageParams.makeKeychainStorageParams(appName: "test")),
                                             cloudKeyStorage: cloudKeyStorage)
        let params = try! KeychainStorageParams.makeKeychainStorageParams(appName: "test")
    #elseif os(iOS) || os(tvOS)
        self.syncKeyStorage = try! SyncKeyStorage(identity: identity, cloudKeyStorage: cloudKeyStorage)
        
        let params = try! KeychainStorageParams.makeKeychainStorageParams()
    #endif

        self.keychainStorage = KeychainStorage(storageParams: params)
        try! self.keychainStorage.deleteAllEntries()
        
        self.keychainStorageWrapper = SandboxedKeychainStorage(identity: identity, keychainStorage: self.keychainStorage)
    }
    
    func test01_KTC29_syncStorage() {
        let _ = try! self.syncKeyStorage.sync().startSync().get()
        XCTAssert(try! self.keychainStorageWrapper.retrieveAllEntries().count == 0)

        var keyEntries = [KeyknoxKeyEntry]()
        
        for _ in 0..<2 {
            let data = NSUUID().uuidString.data(using: .utf8)!
            let name = NSUUID().uuidString
            
            let keyEntry = KeyknoxKeyEntry(name: name, data: data)
            
            keyEntries.append(keyEntry)
        }

        let _ = try! self.cloudKeyStorage.storeEntries([keyEntries[0]]).startSync().get()
        let _ = try! self.syncKeyStorage.sync().startSync().get()
        let keychainEntries = try! self.keychainStorageWrapper.retrieveAllEntries()
        XCTAssert(keychainEntries.count == 1)
        XCTAssert(keychainEntries[0].name == keyEntries[0].name)
        XCTAssert(keychainEntries[0].data == keyEntries[0].data)

        let keychainEntries2 = try! self.keychainStorageWrapper.retrieveAllEntries()
        XCTAssert(keychainEntries2.count == 1)
        XCTAssert(keychainEntries2[0].name == keyEntries[0].name)
        XCTAssert(keychainEntries2[0].data == keyEntries[0].data)
        
        let _ = try! self.cloudKeyStorage.storeEntries([keyEntries[1]]).startSync().get()
        let _ = try! self.syncKeyStorage.sync().startSync().get()
        let keychainEntries3 = try! self.keychainStorageWrapper.retrieveAllEntries()
        XCTAssert(keychainEntries3.count == 2)
        if let keychainEntry = keychainEntries3.first(where: { $0.name == keyEntries[1].name }) {
            XCTAssert(keychainEntry.data == keyEntries[1].data)
        }
        else {
            XCTFail()
        }
        
        try! self.keychainStorage.deleteAllEntries()
        let _ = try! self.syncKeyStorage.sync().startSync().get()
        let keychainEntries4 = try! self.keychainStorageWrapper.retrieveAllEntries()
        XCTAssert(keychainEntries4.count == 2)
        if let keychainEntry = keychainEntries4.first(where: { $0.name == keyEntries[0].name }) {
            XCTAssert(keychainEntry.data == keyEntries[0].data)
        }
        else {
            XCTFail()
        }
        if let keychainEntry = keychainEntries4.first(where: { $0.name == keyEntries[1].name }) {
            XCTAssert(keychainEntry.data == keyEntries[1].data)
        }
        else {
            XCTFail()
        }

        let _ = try! self.cloudKeyStorage.deleteEntry(withName: keyEntries[0].name).startSync().get()
        let _ = try! self.syncKeyStorage.sync().startSync().get()
        let keychainEntries5 = try! self.keychainStorageWrapper.retrieveAllEntries()
        XCTAssert(keychainEntries5.count == 1)
        XCTAssert(keychainEntries5[0].name == keyEntries[1].name)
        XCTAssert(keychainEntries5[0].data == keyEntries[1].data)
        
        let data = NSUUID().uuidString.data(using: .utf8)!
        let _ = try! self.cloudKeyStorage.updateEntry(withName: keyEntries[1].name, data: data).startSync().get()
        let _ = try! self.syncKeyStorage.sync().startSync().get()
        let keychainEntries6 = try! self.keychainStorageWrapper.retrieveAllEntries()
        XCTAssert(keychainEntries6.count == 1)
        XCTAssert(keychainEntries6[0].name == keyEntries[1].name)
        XCTAssert(keychainEntries6[0].data == data)
        
        let _ = try! self.cloudKeyStorage.deleteAllEntries().startSync().get()
        let _ = try! self.syncKeyStorage.sync().startSync().get()
        XCTAssert(try! self.keychainStorageWrapper.retrieveAllEntries().count == 0)
    }
    
    func test02_KTC30_storeEntry() {
        let _ = try! self.cloudKeyStorage.retrieveCloudEntries().startSync().get()
        let _ = try! self.syncKeyStorage.sync().startSync().get()
        
        XCTAssert(try! self.keychainStorageWrapper.retrieveAllEntries().count == 0)
        
        let data = NSUUID().uuidString.data(using: .utf8)!
        let name = NSUUID().uuidString
        let _ = try! self.syncKeyStorage.storeEntry(withName: name, data: data).startSync().get()
        
        let _ = try! self.cloudKeyStorage.retrieveCloudEntries().startSync().get()
        
        let entry = try! self.cloudKeyStorage.retrieveEntry(withName: name)
        
        XCTAssert(try! self.cloudKeyStorage.retrieveAllEntries().count == 1)
        XCTAssert(entry.name == name)
        XCTAssert(entry.data == data)
        
        let keychainEntry = try! self.keychainStorageWrapper.retrieveEntry(withName: name)
        XCTAssert(keychainEntry.name == name)
        XCTAssert(keychainEntry.data == data)
        
        let keychainEntry2 = try! self.syncKeyStorage.retrieveEntry(withName: name)
        XCTAssert(keychainEntry2.name == name)
        XCTAssert(keychainEntry2.data == data)
    }
    
    func test03_KTC31_deleteEntry() {
        let _ = try! self.cloudKeyStorage.retrieveCloudEntries().startSync().get()
        let _ = try! self.syncKeyStorage.sync().startSync().get()
        
        XCTAssert(try! self.keychainStorageWrapper.retrieveAllEntries().count == 0)
        
        let data1 = NSUUID().uuidString.data(using: .utf8)!
        let name1 = NSUUID().uuidString
        let _ = try! self.syncKeyStorage.storeEntry(withName: name1, data: data1).startSync().get()
        
        let data2 = NSUUID().uuidString.data(using: .utf8)!
        let name2 = NSUUID().uuidString
        let _ = try! self.syncKeyStorage.storeEntry(withName: name2, data: data2).startSync().get()
        
        let _ = try! self.cloudKeyStorage.retrieveCloudEntries().startSync().get()
        
        XCTAssert(try! self.cloudKeyStorage.retrieveAllEntries().count == 2)
        XCTAssert(try! self.keychainStorageWrapper.retrieveAllEntries().count == 2)
        
        let _ = try! self.syncKeyStorage.deleteEntry(withName: name1).startSync().get()
        
        let _ = try! self.cloudKeyStorage.retrieveCloudEntries().startSync().get()
        
        XCTAssert(try! self.cloudKeyStorage.retrieveAllEntries().count == 1)
        XCTAssert(try! self.keychainStorageWrapper.retrieveAllEntries().count == 1)
        
        let _ = try! self.cloudKeyStorage.retrieveEntry(withName: name2)
        let _ = try! self.keychainStorageWrapper.retrieveEntry(withName: name2)
    }
    
    func test04_KTC32_updateEntry() {
        let _ = try! self.cloudKeyStorage.retrieveCloudEntries().startSync().get()
        let _ = try! self.syncKeyStorage.sync().startSync().get()
        
        XCTAssert(try! self.keychainStorageWrapper.retrieveAllEntries().count == 0)
        
        let data1 = NSUUID().uuidString.data(using: .utf8)!
        let name = NSUUID().uuidString
        let _ = try! self.syncKeyStorage.storeEntry(withName: name, data: data1).startSync().get()
        
        let data2 = NSUUID().uuidString.data(using: .utf8)!
        
        let _ = try! self.syncKeyStorage.updateEntry(withName: name, data: data2, meta: nil).startSync().get()
        
        let _ = try! self.cloudKeyStorage.retrieveCloudEntries().startSync().get()
        
        let cloudEntry = try! self.cloudKeyStorage.retrieveEntry(withName: name)
        XCTAssert(cloudEntry.name == name)
        XCTAssert(cloudEntry.data == data2)
        
        let keychainEntry = try! self.keychainStorageWrapper.retrieveEntry(withName: name)
        XCTAssert(keychainEntry.name == name)
        XCTAssert(keychainEntry.data == data2)
    }
    
    func test05_KTC33_updateRecipients() {
        let _ = try! self.syncKeyStorage.sync().startSync().get()
        
        let data = NSUUID().uuidString.data(using: .utf8)!
        let name = NSUUID().uuidString
        let _ = try! self.syncKeyStorage.storeEntry(withName: name, data: data).startSync().get()
        
        let keyPair = try! self.crypto.generateKeyPair()
        let newPublicKeys = [keyPair.publicKey, try! self.crypto.generateKeyPair().publicKey]
        let newPrivateKey = keyPair.privateKey
        
        _ = try! self.syncKeyStorage.updateRecipients(newPublicKeys: newPublicKeys, newPrivateKey: newPrivateKey).startSync().get()

        let cloudKeyStorage = self.syncKeyStorage.cloudKeyStorage as! CloudKeyStorage
        let pubIds = (cloudKeyStorage.publicKeys).map { $0.identifier }
        XCTAssert(pubIds == newPublicKeys.map { $0.identifier })
        XCTAssert((cloudKeyStorage.privateKey).identifier == newPrivateKey.identifier)

        let keychainEntry2 = try! self.syncKeyStorage.retrieveEntry(withName: name)
        XCTAssert(keychainEntry2.name == name)
        XCTAssert(keychainEntry2.data == data)

        _ = try! self.syncKeyStorage.sync().startSync().get()

        let keychainEntry3 = try! self.syncKeyStorage.retrieveEntry(withName: name)
        XCTAssert(keychainEntry3.name == name)
        XCTAssert(keychainEntry3.data == data)
    }
    
    func test06_KTC34_storeEntries() {
        let _ = try! self.cloudKeyStorage.retrieveCloudEntries().startSync().get()
        let _ = try! self.syncKeyStorage.sync().startSync().get()
        
        XCTAssert(try! self.keychainStorageWrapper.retrieveAllEntries().count == 0)
        
        let data1 = NSUUID().uuidString.data(using: .utf8)!
        let name1 = NSUUID().uuidString
        let data2 = NSUUID().uuidString.data(using: .utf8)!
        let name2 = NSUUID().uuidString
        let _ = try! self.syncKeyStorage.storeEntries([KeyknoxKeyEntry(name: name1, data: data1),
                                                       KeyknoxKeyEntry(name: name2, data: data2)]).startSync().get()
        
        let _ = try! self.cloudKeyStorage.retrieveCloudEntries().startSync().get()
        
        let entry1 = try! self.cloudKeyStorage.retrieveEntry(withName: name1)
        let entry2 = try! self.cloudKeyStorage.retrieveEntry(withName: name2)
        
        XCTAssert(try! self.cloudKeyStorage.retrieveAllEntries().count == 2)
        XCTAssert(entry1.name == name1)
        XCTAssert(entry1.data == data1)
        XCTAssert(entry2.name == name2)
        XCTAssert(entry2.data == data2)
        
        let keychainEntry1 = try! self.keychainStorageWrapper.retrieveEntry(withName: name1)
        let keychainEntry2 = try! self.keychainStorageWrapper.retrieveEntry(withName: name2)
        XCTAssert(keychainEntry1.name == name1)
        XCTAssert(keychainEntry1.data == data1)
        XCTAssert(keychainEntry2.name == name2)
        XCTAssert(keychainEntry2.data == data2)
        
        let syncKeychainEntry1 = try! self.syncKeyStorage.retrieveEntry(withName: name1)
        let syncKeychainEntry2 = try! self.syncKeyStorage.retrieveEntry(withName: name2)
        XCTAssert(syncKeychainEntry1.name == name1)
        XCTAssert(syncKeychainEntry1.data == data1)
        XCTAssert(syncKeychainEntry2.name == name2)
        XCTAssert(syncKeychainEntry2.data == data2)
    }
    
    func test07_KTC35_deleteEntries() {
        let _ = try! self.cloudKeyStorage.retrieveCloudEntries().startSync().get()
        let _ = try! self.syncKeyStorage.sync().startSync().get()
        
        XCTAssert(try! self.keychainStorageWrapper.retrieveAllEntries().count == 0)
        
        let data1 = NSUUID().uuidString.data(using: .utf8)!
        let name1 = NSUUID().uuidString
        let data2 = NSUUID().uuidString.data(using: .utf8)!
        let name2 = NSUUID().uuidString
        let data3 = NSUUID().uuidString.data(using: .utf8)!
        let name3 = NSUUID().uuidString
        let _ = try! self.syncKeyStorage.storeEntries([KeyknoxKeyEntry(name: name1, data: data1),
                                                       KeyknoxKeyEntry(name: name2, data: data2),
                                                       KeyknoxKeyEntry(name: name3, data: data3)]).startSync().get()
        
        _ = try! self.syncKeyStorage.deleteEntries(withNames: [name1, name2]).startSync().get()
        
        _ = try! self.cloudKeyStorage.retrieveCloudEntries().startSync().get()
        
        XCTAssert(try! self.cloudKeyStorage.retrieveAllEntries().count == 1)
        XCTAssert(try! self.keychainStorageWrapper.retrieveAllEntries().count == 1)
        XCTAssert(try! self.syncKeyStorage.retrieveAllEntries().count == 1)
        
        let entry = try! self.cloudKeyStorage.retrieveEntry(withName: name3)
        XCTAssert(entry.name == name3)
        XCTAssert(entry.data == data3)
        
        let keychainEntry = try! self.keychainStorageWrapper.retrieveEntry(withName: name3)
        XCTAssert(keychainEntry.name == name3)
        XCTAssert(keychainEntry.data == data3)
        
        let syncKeychainEntry = try! self.syncKeyStorage.retrieveEntry(withName: name3)
        XCTAssert(syncKeychainEntry.name == name3)
        XCTAssert(syncKeychainEntry.data == data3)
    }
    
    func test08_KTC36_retrieveAllEntries() {
        let _ = try! self.syncKeyStorage.sync().startSync().get()
        
        let data1 = NSUUID().uuidString.data(using: .utf8)!
        let name1 = NSUUID().uuidString
        let data2 = NSUUID().uuidString.data(using: .utf8)!
        let name2 = NSUUID().uuidString
        
        let _ = try! self.syncKeyStorage.storeEntries([KeyknoxKeyEntry(name: name1, data: data1),
                                                       KeyknoxKeyEntry(name: name2, data: data2)]).startSync().get()
        
        let fakeCloudEntry = CloudEntry(name: "name1", data: Data(), creationDate: Date(), modificationDate: Date(), meta: nil)
        
        // Add some random keys
        _ = try! self.keychainStorage.store(data: Data(), withName: "name1", meta: nil)
        _ = try! self.keychainStorage.store(data: Data(), withName: "name2", meta: KeychainUtils().createMetaForKeychain(from: fakeCloudEntry))
        
        let allEntries = try! self.syncKeyStorage.retrieveAllEntries()
        
        XCTAssert(allEntries.count == 2)
        
        let syncKeychainEntry1 = try! self.syncKeyStorage.retrieveEntry(withName: name1)
        let syncKeychainEntry2 = try! self.syncKeyStorage.retrieveEntry(withName: name2)
        XCTAssert(syncKeychainEntry1.name == name1)
        XCTAssert(syncKeychainEntry1.data == data1)
        XCTAssert(syncKeychainEntry2.name == name2)
        XCTAssert(syncKeychainEntry2.data == data2)
    }
    
    func test09_KTC37_deleteAllEntries() {
        let _ = try! self.syncKeyStorage.sync().startSync().get()
        
        let data1 = NSUUID().uuidString.data(using: .utf8)!
        let name1 = NSUUID().uuidString
        let data2 = NSUUID().uuidString.data(using: .utf8)!
        let name2 = NSUUID().uuidString
        
        let _ = try! self.syncKeyStorage.storeEntries([KeyknoxKeyEntry(name: name1, data: data1),
                                                       KeyknoxKeyEntry(name: name2, data: data2)]).startSync().get()

        _ = try! self.syncKeyStorage.deleteAllEntries().startSync().get()
        
        _ = try! self.cloudKeyStorage.retrieveCloudEntries().startSync().get()
        XCTAssert(try! self.cloudKeyStorage.retrieveAllEntries().count == 0)
        XCTAssert(try! self.keychainStorage.retrieveAllEntries().count == 0)
        XCTAssert(try! self.syncKeyStorage.retrieveAllEntries().count == 0)
    }
    
    func test10_KTC38_deleteAllEntries_empty() {
        let _ = try! self.syncKeyStorage.sync().startSync().get()
        
        _ = try! self.syncKeyStorage.deleteAllEntries().startSync().get()
        
        _ = try! self.cloudKeyStorage.retrieveCloudEntries().startSync().get()
        XCTAssert(try! self.cloudKeyStorage.retrieveAllEntries().count == 0)
        XCTAssert(try! self.keychainStorage.retrieveAllEntries().count == 0)
        XCTAssert(try! self.syncKeyStorage.retrieveAllEntries().count == 0)
    }
    
    func test11_KTC39_existsEntry() {
        let _ = try! self.syncKeyStorage.sync().startSync().get()
        
        let data = NSUUID().uuidString.data(using: .utf8)!
        let name1 = NSUUID().uuidString
        let name2 = NSUUID().uuidString
        let _ = try! self.syncKeyStorage.storeEntry(withName: name1, data: data).startSync().get()
        
        XCTAssert(try! self.syncKeyStorage.existsEntry(withName: name1))
        XCTAssert(!(try! self.syncKeyStorage.existsEntry(withName: name2)))
    }
    
    func test12_KTC40_outOfSyncError() {
        let testName = NSUUID().uuidString
        
        _ = try! keychainStorageWrapper.store(data: NSUUID().uuidString.data(using: .utf8)!, withName: testName, meta: nil)

        do {
            try self.syncKeyStorage.deleteEntry(withName: testName).startSync().get()
            XCTFail()
        }
        catch CloudKeyStorageError.cloudStorageOutOfSync { }
        catch {
            XCTFail()
        }
        
        do {
            _ = try self.syncKeyStorage.deleteEntries(withNames: [testName]).startSync().get()
            XCTFail()
        }
        catch CloudKeyStorageError.cloudStorageOutOfSync { }
        catch {
            XCTFail()
        }
        
        do {
            _ = try self.syncKeyStorage.storeEntry(withName: "", data: Data()).startSync().get()
            XCTFail()
        }
        catch CloudKeyStorageError.cloudStorageOutOfSync { }
        catch {
            XCTFail()
        }
        
        do {
            _ = try self.syncKeyStorage.storeEntries([KeyknoxKeyEntry(name: "", data: Data())]).startSync().get()
            XCTFail()
        }
        catch CloudKeyStorageError.cloudStorageOutOfSync { }
        catch {
            XCTFail()
        }

        XCTAssert(try! self.syncKeyStorage.existsEntry(withName: testName))
        _ = try! self.syncKeyStorage.retrieveAllEntries()
        _ = try! self.syncKeyStorage.retrieveEntry(withName: testName)
        
        do {
            _ = try self.syncKeyStorage.updateEntry(withName: testName, data: Data(), meta: nil).startSync().get()
            XCTFail()
        }
        catch SyncKeyStorageError.cloudEntryNotFoundWhileUpdating { }
        catch {
            XCTFail()
        }
        
        do {
            _ = try self.syncKeyStorage.updateRecipients(newPublicKeys: [try!self.crypto.generateKeyPair().publicKey], newPrivateKey: try!self.crypto.generateKeyPair().privateKey).startSync().get()
            XCTFail()
        }
        catch CloudKeyStorageError.cloudStorageOutOfSync { }
        catch {
            XCTFail()
        }
    }
}
