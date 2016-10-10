//
//  VSSSearchCardsPrivate.h
//  VirgilSDK
//
//  Created by Oleksandr Deundiak on 10/7/16.
//  Copyright © 2016 VirgilSecurity. All rights reserved.
//

#import "VSSSearchCards.h"
#import "VSSSerializable.h"

@interface VSSSearchCards () <VSSSerializable>

- (instancetype __nonnull)initWithScope:(VSSCardScope)scope identityType:(NSString * __nonnull)identityType identities:(NSArray<NSString *>* __nonnull)indentities;

@end