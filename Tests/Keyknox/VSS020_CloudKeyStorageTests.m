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

#import "VSSTestBase.h"

static const NSTimeInterval timeout = 20.;

@interface VSS003_CloudKeyStorageTests : VSSTestBase

@property (nonatomic) VSMVirgilKeyPair *keyPair;
@property (nonatomic) VSSCloudKeyStorage *keyStorage;
@property (nonatomic) VSSKeyknoxManager *keyknoxManager;
@property (nonatomic) NSInteger numberOfKeys;
@property (nonatomic) NSString *identity;

@end

@implementation VSS003_CloudKeyStorageTests

- (void)setUp {
    [super setUp];

    NSString *identity = [[NSUUID alloc] init].UUIDString;

    self.identity = identity;

    VSMVirgilKeyPair *keyPair = [self.crypto generateKeyPairAndReturnError:nil];
    self.keyPair = keyPair;

    VSSKeyknoxClient *keyknoxClient = [self.utils setupKeyknoxClientWithIdentity:identity];

    VSSKeyknoxManager *keyknoxManager = [self.utils setupKeyknoxManagerWithClient:keyknoxClient crypto:self.crypto];

    self.keyknoxManager = keyknoxManager;
    
    self.keyStorage = [[VSSCloudKeyStorage alloc] initWithKeyknoxManager:keyknoxManager
                                                              publicKeys:@[keyPair.publicKey]
                                                              privateKey:keyPair.privateKey];
}

- (void)tearDown {
    [super tearDown];
}

- (void)test01_KTC19_retrieveCloudEntriesEmptyKeyknox {
    XCTestExpectation *ex = [self expectationWithDescription:@""];
    
    [self.keyStorage retrieveCloudEntriesWithCompletion:^(NSError *error) {
        XCTAssert(error == nil);
        NSError *err;
        XCTAssert([self.keyStorage retrieveAllEntriesAndReturnError:&err].count == 0);
        XCTAssert(err == nil);
        
        [ex fulfill];
    }];
    
    [self waitForExpectationsWithTimeout:timeout handler:^(NSError *error) {
        if (error != nil)
            XCTFail(@"Expectation failed: %@", error);
    }];
}

- (void)test02_KTC20_storeKey {
    XCTestExpectation *ex = [self expectationWithDescription:@""];
    
    VSMVirgilKeyPair *keyPair = [self.crypto generateKeyPairAndReturnError:nil];
    NSData *privateKeyData = [self.crypto exportPrivateKey:keyPair.privateKey error:nil];
    NSString *name = @"test";
    NSDictionary *meta = @{
                           @"test_key": @"test_value"
                           };
    [self.keyStorage retrieveCloudEntriesWithCompletion:^(NSError *error) {
        [self.keyStorage storeEntryWithName:name data:privateKeyData meta:meta completion:^(NSError *error) {
            XCTAssert(error == nil);
            NSError *err;
            XCTAssert([self.keyStorage retrieveAllEntriesAndReturnError:&err].count == 1);
            XCTAssert(err == nil);
            
            VSSCloudEntry *entry = [self.keyStorage retrieveEntryWithName:name error:&err];
            XCTAssert(err == nil);
            VSMVirgilPrivateKey *privateKey = [self.crypto importPrivateKeyFrom:entry.data error:nil].privateKey;
            XCTAssert([privateKey.identifier isEqualToData:keyPair.privateKey.identifier]);
            XCTAssert([entry.name isEqualToString:name]);
            XCTAssert(entry.creationDate.timeIntervalSinceNow < 5);
            XCTAssert([entry.creationDate isEqualToDate:entry.modificationDate]);
            XCTAssert([entry.meta isEqualToDictionary:meta]);
            
            [self.keyStorage retrieveCloudEntriesWithCompletion:^(NSError *error) {
                XCTAssert(error == nil);
                NSError *err;
                XCTAssert([self.keyStorage retrieveAllEntriesAndReturnError:&err].count == 1);
                XCTAssert(err == nil);
                
                VSSCloudEntry *entry = [self.keyStorage retrieveEntryWithName:name error:&err];
                XCTAssert(err == nil);
                VSMVirgilPrivateKey *privateKey = [self.crypto importPrivateKeyFrom:entry.data error:nil].privateKey;
                XCTAssert([privateKey.identifier isEqualToData:keyPair.privateKey.identifier]);
                XCTAssert([entry.name isEqualToString:name]);
                XCTAssert(entry.creationDate.timeIntervalSinceNow < 5);
                XCTAssert([entry.creationDate isEqualToDate:entry.modificationDate]);
                XCTAssert([entry.meta isEqualToDictionary:meta]);
                
                [ex fulfill];
            }];
        }];
    }];
    
    [self waitForExpectationsWithTimeout:timeout handler:^(NSError *error) {
        if (error != nil)
            XCTFail(@"Expectation failed: %@", error);
    }];
}

- (void)test03_KTC21_existsKey {
    XCTestExpectation *ex = [self expectationWithDescription:@""];

    VSMVirgilKeyPair *keyPair = [self.crypto generateKeyPairAndReturnError:nil];
    NSData *privateKeyData = [self.crypto exportPrivateKey:keyPair.privateKey error:nil];

    [self.keyStorage retrieveCloudEntriesWithCompletion:^(NSError *error) {
        [self.keyStorage storeEntryWithName:@"test" data:privateKeyData meta:nil completion:^(NSError *error) {
            XCTAssert(error == nil);
            NSError *err;
            XCTAssert([self.keyStorage retrieveAllEntriesAndReturnError:&err].count == 1);
            XCTAssert(err == nil);

            XCTAssert([self.keyStorage existsEntryNoThrowWithName:@"test"]);
            XCTAssert(![self.keyStorage existsEntryNoThrowWithName:@"test2"]);

            [self.keyStorage retrieveCloudEntriesWithCompletion:^(NSError *error) {
                XCTAssert(error == nil);
                NSError *err;
                XCTAssert([self.keyStorage retrieveAllEntriesAndReturnError:&err].count == 1);
                XCTAssert(err == nil);

                XCTAssert([self.keyStorage existsEntryNoThrowWithName:@"test"]);
                XCTAssert(![self.keyStorage existsEntryNoThrowWithName:@"test2"]);

                [ex fulfill];
            }];
        }];
    }];

    [self waitForExpectationsWithTimeout:timeout handler:^(NSError *error) {
        if (error != nil)
            XCTFail(@"Expectation failed: %@", error);
    }];
}

- (void)test04_KTC22_storeMultipleKeys {
    XCTestExpectation *ex = [self expectationWithDescription:@""];

    int numberOfKeys = 100;

    NSMutableArray<VSMVirgilPrivateKey *> *privateKeys = [[NSMutableArray alloc] init];
    NSMutableArray<VSSKeyknoxKeyEntry *> *keyEntries = [[NSMutableArray alloc] init];

    for (int i = 0; i < numberOfKeys; i++) {
        VSMVirgilKeyPair *keyPair = [self.crypto generateKeyPairAndReturnError:nil];

        [privateKeys addObject:keyPair.privateKey];

        if (i > 0 && i < numberOfKeys - 1) {
            NSString *name = [NSString stringWithFormat:@"%d", i];
            NSData *data = [self.crypto exportPrivateKey:keyPair.privateKey error:nil];
            VSSKeyknoxKeyEntry *keyEntry = [[VSSKeyknoxKeyEntry alloc] initWithName:name data:data meta:nil];
            
            [keyEntries addObject:keyEntry];
        }
    }

    NSData *privateKeyData = [self.crypto exportPrivateKey:privateKeys[0] error:nil];
    [self.keyStorage retrieveCloudEntriesWithCompletion:^(NSError *error) {
        [self.keyStorage storeEntryWithName:@"first" data:privateKeyData meta:nil completion:^(NSError *error) {
            [self.keyStorage storeEntries:keyEntries completion:^(NSError *error) {
                XCTAssert(error == nil);
                NSError *err;
                XCTAssert([self.keyStorage retrieveAllEntriesAndReturnError:&err].count == numberOfKeys - 1);
                XCTAssert(err == nil);
                VSMVirgilPrivateKey *privateKey = [self.crypto importPrivateKeyFrom:[self.keyStorage retrieveEntryWithName:@"first" error:&err].data error:nil].privateKey;
                XCTAssert(err == nil);
                XCTAssert([privateKey.identifier isEqualToData:privateKeys[0].identifier]);
                for (int i = 1; i < numberOfKeys - 1; i++) {
                    NSString *name = [NSString stringWithFormat:@"%d", i];
                    VSMVirgilPrivateKey *privateKey = [self.crypto importPrivateKeyFrom:[self.keyStorage retrieveEntryWithName:name error:&err].data error:nil].privateKey;
                    XCTAssert(err == nil);
                    XCTAssert([privateKey.identifier isEqualToData:privateKeys[i].identifier]);
                }

                [self.keyStorage retrieveCloudEntriesWithCompletion:^(NSError *error) {
                    XCTAssert(error == nil);
                    NSError *err;
                    XCTAssert([self.keyStorage retrieveAllEntriesAndReturnError:&err].count == numberOfKeys - 1);
                    XCTAssert(err == nil);
                    VSMVirgilPrivateKey *privateKey = [self.crypto importPrivateKeyFrom:[self.keyStorage retrieveEntryWithName:@"first" error:&err].data error:nil].privateKey;
                    XCTAssert(err == nil);
                    XCTAssert([privateKey.identifier isEqualToData:privateKeys[0].identifier]);
                    for (int i = 1; i < numberOfKeys - 1; i++) {
                        NSString *name = [NSString stringWithFormat:@"%d", i];
                        VSMVirgilPrivateKey *privateKey = [self.crypto importPrivateKeyFrom:[self.keyStorage retrieveEntryWithName:name error:&err].data error:nil].privateKey;
                        XCTAssert(err == nil);
                        XCTAssert([privateKey.identifier isEqualToData:privateKeys[i].identifier]);
                    }

                    NSData *privateKeyData = [self.crypto exportPrivateKey:privateKeys[numberOfKeys - 1] error:nil];
                    [self.keyStorage storeEntryWithName:@"last" data:privateKeyData meta:nil completion:^(NSError *error) {
                        XCTAssert(error == nil);
                        NSError *err;
                        XCTAssert([self.keyStorage retrieveAllEntriesAndReturnError:&err].count == numberOfKeys);
                        XCTAssert(err == nil);
                        VSMVirgilPrivateKey *privateKey = [self.crypto importPrivateKeyFrom:[self.keyStorage retrieveEntryWithName:@"first" error:&err].data error:nil].privateKey;
                        XCTAssert(err == nil);
                        XCTAssert([privateKey.identifier isEqualToData:privateKeys[0].identifier]);
                        for (int i = 1; i < numberOfKeys - 1; i++) {
                            NSString *name = [NSString stringWithFormat:@"%d", i];
                            VSMVirgilPrivateKey *privateKey = [self.crypto importPrivateKeyFrom:[self.keyStorage retrieveEntryWithName:name error:&err].data error:nil].privateKey;
                            XCTAssert(err == nil);
                            XCTAssert([privateKey.identifier isEqualToData:privateKeys[i].identifier]);
                        }
                        VSMVirgilPrivateKey *lastPrivateKey = [self.crypto importPrivateKeyFrom:[self.keyStorage retrieveEntryWithName:@"last" error:&err].data error:nil].privateKey;
                        XCTAssert(err == nil);
                        XCTAssert([lastPrivateKey.identifier isEqualToData:privateKeys[numberOfKeys - 1].identifier]);

                        [self.keyStorage retrieveCloudEntriesWithCompletion:^(NSError *error) {
                            XCTAssert(error == nil);
                            NSError *err;
                            XCTAssert([self.keyStorage retrieveAllEntriesAndReturnError:&err].count == numberOfKeys);
                            XCTAssert(err == nil);
                            VSMVirgilPrivateKey *privateKey = [self.crypto importPrivateKeyFrom:[self.keyStorage retrieveEntryWithName:@"first" error:&err].data error:nil].privateKey;
                            XCTAssert(err == nil);
                            XCTAssert([privateKey.identifier isEqualToData:privateKeys[0].identifier]);
                            for (int i = 1; i < numberOfKeys - 1; i++) {
                                NSString *name = [NSString stringWithFormat:@"%d", i];
                                VSMVirgilPrivateKey *privateKey = [self.crypto importPrivateKeyFrom:[self.keyStorage retrieveEntryWithName:name error:&err].data error:nil].privateKey;
                                XCTAssert(err == nil);
                                XCTAssert([privateKey.identifier isEqualToData:privateKeys[i].identifier]);
                            }
                            VSMVirgilPrivateKey *lastPrivateKey = [self.crypto importPrivateKeyFrom:[self.keyStorage retrieveEntryWithName:@"last" error:&err].data error:nil].privateKey;
                            XCTAssert(err == nil);
                            XCTAssert([lastPrivateKey.identifier isEqualToData:privateKeys[numberOfKeys - 1].identifier]);

                            [ex fulfill];
                        }];
                    }];
                }];
            }];
        }];
    }];

    [self waitForExpectationsWithTimeout:timeout + numberOfKeys / 4 handler:^(NSError *error) {
        if (error != nil)
            XCTFail(@"Expectation failed: %@", error);
    }];
}

- (void)test05_KTC23_deleteAllKeys {
    XCTestExpectation *ex = [self expectationWithDescription:@""];

    int numberOfKeys = 100;

    NSMutableArray<VSSKeyknoxKeyEntry *> *keyEntries = [[NSMutableArray alloc] init];

    for (int i = 0; i < numberOfKeys; i++) {
        VSMVirgilKeyPair *keyPair = [self.crypto generateKeyPairAndReturnError:nil];
        NSString *name = [NSString stringWithFormat:@"%d", i];
        NSData *privateKeyData = [self.crypto exportPrivateKey:keyPair.privateKey error:nil];
        VSSKeyknoxKeyEntry *keyEntry = [[VSSKeyknoxKeyEntry alloc] initWithName:name data:privateKeyData meta:nil];
        [keyEntries addObject:keyEntry];
    }

    [self.keyStorage retrieveCloudEntriesWithCompletion:^(NSError *error) {
        [self.keyStorage storeEntries:keyEntries completion:^(NSError *error) {
            [self.keyStorage deleteAllEntriesWithCompletion:^(NSError *error) {
                XCTAssert(error == nil);
                NSError *err;
                XCTAssert([self.keyStorage retrieveAllEntriesAndReturnError:&err].count == 0);
                XCTAssert(err == nil);

                [self.keyStorage retrieveCloudEntriesWithCompletion:^(NSError *error) {
                    XCTAssert(error == nil);
                    NSError *err;
                    XCTAssert([self.keyStorage retrieveAllEntriesAndReturnError:&err].count == 0);
                    XCTAssert(err == nil);

                    [ex fulfill];
                }];
            }];
        }];
    }];

    [self waitForExpectationsWithTimeout:timeout + numberOfKeys / 4 handler:^(NSError *error) {
        if (error != nil)
            XCTFail(@"Expectation failed: %@", error);
    }];
}

- (void)test06_KTC24_deleteAllKeysEmpty {
    XCTestExpectation *ex = [self expectationWithDescription:@""];
    
    [self.keyStorage deleteAllEntriesWithCompletion:^(NSError *error) {
        XCTAssert(error == nil);
        NSError *err;
        XCTAssert([self.keyStorage retrieveAllEntriesAndReturnError:&err].count == 0);
        XCTAssert(err == nil);
        
        [self.keyStorage retrieveCloudEntriesWithCompletion:^(NSError *error) {
            XCTAssert(error == nil);
            NSError *err;
            XCTAssert([self.keyStorage retrieveAllEntriesAndReturnError:&err].count == 0);
            XCTAssert(err == nil);
            
            [ex fulfill];
        }];
    }];
    
    [self waitForExpectationsWithTimeout:timeout handler:^(NSError *error) {
        if (error != nil)
            XCTFail(@"Expectation failed: %@", error);
    }];
}

- (void)test07_KTC25_deleteKeys {
    XCTestExpectation *ex = [self expectationWithDescription:@""];
    
    int numberOfKeys = 10;
    
    NSMutableArray<VSSKeyknoxKeyEntry *> *keyEntries = [[NSMutableArray alloc] init];
    
    for (int i = 0; i < numberOfKeys; i++) {
        VSMVirgilKeyPair *keyPair = [self.crypto generateKeyPairAndReturnError:nil];
        NSString *name = [NSString stringWithFormat:@"%d", i];
        NSData *privateKeyData = [self.crypto exportPrivateKey:keyPair.privateKey error:nil];
        VSSKeyknoxKeyEntry *keyEntry = [[VSSKeyknoxKeyEntry alloc] initWithName:name data:privateKeyData meta:nil];
        [keyEntries addObject:keyEntry];
    }
    
    [self.keyStorage retrieveCloudEntriesWithCompletion:^(NSError *error) {
        [self.keyStorage storeEntries:keyEntries completion:^(NSError *error) {
            [self.keyStorage deleteEntryWithName:keyEntries[0].name completion:^(NSError *error) {
                XCTAssert(error == nil);
                
                NSError *err;
                XCTAssert([self.keyStorage retrieveAllEntriesAndReturnError:&err].count == numberOfKeys - 1);
                XCTAssert(err == nil);
                
                VSSCloudEntry *keyEntry = [self.keyStorage retrieveEntryWithName:keyEntries[0].name error:&err];
                XCTAssert(keyEntry == nil && err != nil);
                
                [self.keyStorage deleteEntriesWithNames:@[keyEntries[1].name, keyEntries[2].name] completion:^(NSError *error) {
                    XCTAssert(error == nil);
                    
                    NSError *err;
                    XCTAssert([self.keyStorage retrieveAllEntriesAndReturnError:&err].count == numberOfKeys - 3);
                    XCTAssert(err == nil);
                    
                    VSSCloudEntry *keyEntry = [self.keyStorage retrieveEntryWithName:keyEntries[1].name error:&err];
                    XCTAssert(keyEntry == nil && err != nil);
                    
                    keyEntry = [self.keyStorage retrieveEntryWithName:keyEntries[2].name error:&err];
                    XCTAssert(keyEntry == nil && err != nil);
                    
                    [self.keyStorage retrieveCloudEntriesWithCompletion:^(NSError *error) {
                        XCTAssert(error == nil);
                        
                        NSError *err;
                        
                        XCTAssert([self.keyStorage retrieveAllEntriesAndReturnError:&err].count == numberOfKeys - 3);
                        XCTAssert(err == nil);
                        
                        VSSCloudEntry *keyEntry = [self.keyStorage retrieveEntryWithName:keyEntries[0].name error:&err];
                        XCTAssert(keyEntry == nil && err != nil);
                        
                        keyEntry = [self.keyStorage retrieveEntryWithName:keyEntries[1].name error:&err];
                        XCTAssert(keyEntry == nil && err != nil);
                        
                        keyEntry = [self.keyStorage retrieveEntryWithName:keyEntries[2].name error:&err];
                        XCTAssert(keyEntry == nil && err != nil);
                        
                        [ex fulfill];
                    }];
                }];
            }];
        }];
    }];
    
    [self waitForExpectationsWithTimeout:timeout + numberOfKeys / 4 handler:^(NSError *error) {
        if (error != nil)
            XCTFail(@"Expectation failed: %@", error);
    }];
}

- (void)test08_KTC26_updateEntry {
    XCTestExpectation *ex = [self expectationWithDescription:@""];
    
    int numberOfKeys = 10;
    
    NSMutableArray<VSSKeyknoxKeyEntry *> *keyEntries = [[NSMutableArray alloc] init];
    
    for (int i = 0; i < numberOfKeys; i++) {
        VSMVirgilKeyPair *keyPair = [self.crypto generateKeyPairAndReturnError:nil];
        NSString *name = [NSString stringWithFormat:@"%d", i];
        NSData *privateKeyData = [self.crypto exportPrivateKey:keyPair.privateKey error:nil];
        VSSKeyknoxKeyEntry *keyEntry = [[VSSKeyknoxKeyEntry alloc] initWithName:name data:privateKeyData meta:nil];
        [keyEntries addObject:keyEntry];
    }
    
    [self.keyStorage retrieveCloudEntriesWithCompletion:^(NSError *error) {
        [self.keyStorage storeEntries:keyEntries completion:^(NSError *error) {
            NSDictionary *meta = @{@"key": @"value"};
            [self.keyStorage updateEntryWithName:keyEntries[0].name
                                            data:keyEntries[1].data
                                            meta:meta
                                      completion:^(VSSCloudEntry *cloudEntry, NSError *error) {
                XCTAssert(cloudEntry != nil && error == nil);
                
                XCTAssert([cloudEntry.name isEqualToString:keyEntries[0].name]);
                XCTAssert([cloudEntry.data isEqualToData:keyEntries[1].data]);
                XCTAssert([cloudEntry.meta isEqualToDictionary:meta]);
                
                NSError *err;
                VSSCloudEntry *cloudEntry2 = [self.keyStorage retrieveEntryWithName:keyEntries[0].name error:&err];
                XCTAssert(cloudEntry2 != nil && err == nil);
                
                XCTAssert([cloudEntry2.name isEqualToString:keyEntries[0].name]);
                XCTAssert([cloudEntry2.data isEqualToData:keyEntries[1].data]);
                XCTAssert([cloudEntry2.meta isEqualToDictionary:meta]);
                
                [self.keyStorage retrieveCloudEntriesWithCompletion:^(NSError *error) {
                    NSError *err;
                    VSSCloudEntry *cloudEntry = [self.keyStorage retrieveEntryWithName:keyEntries[0].name error:&err];
                    XCTAssert(cloudEntry != nil && err == nil);

                    XCTAssert([cloudEntry.name isEqualToString:keyEntries[0].name]);
                    XCTAssert([cloudEntry.data isEqualToData:keyEntries[1].data]);
                    XCTAssert([cloudEntry.meta isEqualToDictionary:meta]);

                    [ex fulfill];
                }];
            }];
        }];
    }];
    
    [self waitForExpectationsWithTimeout:timeout + numberOfKeys / 4 handler:^(NSError *error) {
        if (error != nil)
            XCTFail(@"Expectation failed: %@", error);
    }];
}

- (void)test09_KTC27_updateRecipients {
    XCTestExpectation *ex = [self expectationWithDescription:@""];
    
    int numberOfKeys = 10;
    
    NSMutableArray<VSSKeyknoxKeyEntry *> *keyEntries = [[NSMutableArray alloc] init];
    
    for (int i = 0; i < numberOfKeys; i++) {
        VSMVirgilKeyPair *keyPair = [self.crypto generateKeyPairAndReturnError:nil];
        NSString *name = [NSString stringWithFormat:@"%d", i];
        NSData *privateKeyData = [self.crypto exportPrivateKey:keyPair.privateKey error:nil];
        VSSKeyknoxKeyEntry *keyEntry = [[VSSKeyknoxKeyEntry alloc] initWithName:name data:privateKeyData meta:nil];
        [keyEntries addObject:keyEntry];
    }
    
    [self.keyStorage retrieveCloudEntriesWithCompletion:^(NSError *error) {
        [self.keyStorage storeEntries:keyEntries completion:^(NSError *error) {
            VSMVirgilKeyPair *keyPair = [self.crypto generateKeyPairAndReturnError:nil];

            [self.keyStorage updateRecipientsWithNewPublicKeys:@[keyPair.publicKey] newPrivateKey:keyPair.privateKey completion:^(NSError *error) {
                XCTAssert(error == nil);
                
                NSError *err;
                XCTAssert([self.keyStorage retrieveAllEntriesAndReturnError:&err].count == numberOfKeys);
                XCTAssert(err == nil);
                
                [self.keyStorage retrieveCloudEntriesWithCompletion:^(NSError *error) {
                    XCTAssert(error == nil);
                    
                    NSError *err;
                    XCTAssert([self.keyStorage retrieveAllEntriesAndReturnError:&err].count == numberOfKeys);
                    XCTAssert(err == nil);

                    [ex fulfill];
                }];
            }];
        }];
    }];
    
    [self waitForExpectationsWithTimeout:timeout + numberOfKeys / 4 handler:^(NSError *error) {
        if (error != nil)
            XCTFail(@"Expectation failed: %@", error);
    }];
}

- (void)test10_KTC28_outOfSyncError {
    XCTestExpectation *ex = [self expectationWithDescription:@""];

    NSError *err;
    NSArray *entries = [self.keyStorage retrieveAllEntriesAndReturnError:&err];
    XCTAssert(entries == nil && [err.domain isEqualToString:VSSCloudKeyStorageErrorDomain] && err.code == VSSCloudKeyStorageErrorCloudStorageOutOfSync);
    err = nil;
    
    VSSCloudEntry *entry = [self.keyStorage retrieveEntryWithName:@"test" error:&err];
    XCTAssert(entry == nil && [err.domain isEqualToString:VSSCloudKeyStorageErrorDomain] && err.code == VSSCloudKeyStorageErrorCloudStorageOutOfSync);
    err = nil;
    
    XCTAssert(![self.keyStorage existsEntryNoThrowWithName:@"test"]);
    
    int numberOfKeys = 10;
    
    NSMutableArray<VSSKeyknoxKeyEntry *> *keyEntries = [[NSMutableArray alloc] init];
    
    for (int i = 0; i < numberOfKeys; i++) {
        VSMVirgilKeyPair *keyPair = [self.crypto generateKeyPairAndReturnError:nil];
        NSString *name = [NSString stringWithFormat:@"%d", i];
        NSData *privateKeyData = [self.crypto exportPrivateKey:keyPair.privateKey error:nil];
        VSSKeyknoxKeyEntry *keyEntry = [[VSSKeyknoxKeyEntry alloc] initWithName:name data:privateKeyData meta:nil];
        [keyEntries addObject:keyEntry];
    }
    
    [self.keyStorage storeEntryWithName:keyEntries[0].name data:keyEntries[0].data meta:nil completion:^(NSError *error) {
        XCTAssert([error.domain isEqualToString:VSSCloudKeyStorageErrorDomain] && error.code == VSSCloudKeyStorageErrorCloudStorageOutOfSync);
        
        [self.keyStorage storeEntries:keyEntries completion:^(NSError *error) {
            XCTAssert([error.domain isEqualToString:VSSCloudKeyStorageErrorDomain] && error.code == VSSCloudKeyStorageErrorCloudStorageOutOfSync);
            
            [self.keyStorage updateEntryWithName:keyEntries[0].name data:keyEntries[0].data meta:nil completion:^(VSSCloudEntry *entry, NSError *error) {
                XCTAssert(entry == nil && [error.domain isEqualToString:VSSCloudKeyStorageErrorDomain] && error.code == VSSCloudKeyStorageErrorCloudStorageOutOfSync);
                
                [self.keyStorage deleteEntryWithName:keyEntries[0].name completion:^(NSError *error) {
                    XCTAssert([error.domain isEqualToString:VSSCloudKeyStorageErrorDomain] && error.code == VSSCloudKeyStorageErrorCloudStorageOutOfSync);
                    
                    [self.keyStorage deleteEntriesWithNames:@[keyEntries[0].name, keyEntries[1].name] completion:^(NSError *error) {
                        XCTAssert([error.domain isEqualToString:VSSCloudKeyStorageErrorDomain] && error.code == VSSCloudKeyStorageErrorCloudStorageOutOfSync);
                        
                        [self.keyStorage updateRecipientsWithNewPublicKeys:@[self.keyPair.publicKey] newPrivateKey:self.keyPair.privateKey completion:^(NSError *error) {
                            XCTAssert([error.domain isEqualToString:VSSCloudKeyStorageErrorDomain] && error.code == VSSCloudKeyStorageErrorCloudStorageOutOfSync);
                            
                            [ex fulfill];
                        }];
                    }];
                }];
            }];
        }];
    }];
    
    [self waitForExpectationsWithTimeout:timeout + numberOfKeys / 4 handler:^(NSError *error) {
        if (error != nil)
            XCTFail(@"Expectation failed: %@", error);
    }];
}

- (void)test11_KTC41_deleteInvalidValue {
    XCTestExpectation *ex = [self expectationWithDescription:@""];

    NSData *data = [[[NSUUID alloc] init].UUIDString dataUsingEncoding:NSUTF8StringEncoding];

    [self.keyknoxManager pushValueWithParams:nil
                                        data:data
                                previousHash:nil
                                  publicKeys:@[self.keyPair.publicKey]
                                  privateKey:self.keyPair.privateKey
                                  completion:^(VSSDecryptedKeyknoxValue *value, NSError *error) {
        XCTAssert(value != nil && error == nil);
        
        [self.keyStorage deleteAllEntriesWithCompletion:^(NSError *error) {
            XCTAssert(error == nil);
            
            NSError *err;
            XCTAssert([self.keyStorage retrieveAllEntriesAndReturnError:&err].count == 0);
            XCTAssert(err == nil);
            
            NSString *name = [[NSUUID alloc] init].UUIDString;
            NSData *data = [[[NSUUID alloc] init].UUIDString dataUsingEncoding:NSUTF8StringEncoding];
            
            [self.keyStorage storeEntryWithName:name data:data meta:nil completion:^(NSError *error) {
                XCTAssert(error == nil);
                
                NSError *err;
                
                VSSCloudEntry *entry = [self.keyStorage retrieveEntryWithName:name error:&err];
                
                XCTAssert(err == nil);
                XCTAssert(entry != nil);
                XCTAssert([entry.name isEqualToString:name]);
                XCTAssert([entry.data isEqualToData:data]);
                
                [ex fulfill];
            }];
        }];
    }];
    
    [self waitForExpectationsWithTimeout:timeout handler:^(NSError *error) {
        if (error != nil)
            XCTFail(@"Expectation failed: %@", error);
    }];
}

@end
