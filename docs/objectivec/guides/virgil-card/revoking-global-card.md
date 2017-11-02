# Revoking Global Card

This guide shows how to revoke a **Global Virgil Card**.

Вefore you begin to revoke a Global Virgil Card, set up your project environment with the [getting started](/docs/objectivec/guides/configuration/client.md) guide.

To revoke a Global Virgil Card, we need to:

-  Initialize the Virgil SDK

```objectivec
// this language is not supported yet.
```

- Load Alice's **Virgil Key** from the secure storage provided by default
- Load Alice's Virgil Card from **Virgil Services**
- Initiate the Card identity verification process
- Confirm the Card identity using a **confirmation code**
- Revoke the Global Virgil Card from Virgil Services

```objectivec
// load a Virgil Key from storage
VSSVirgilKey *aliceKey = [virgil.keys loadKeyWithName:@"[KEY_NAME]"
	password:@"[OPTIONAL_KEY_PASSWORD]" error:nil];

// load a Virgil Card from Virgil Services
[virgil.cards getCardWithId:@"[USER_CARD_ID_HERE]"
	completion:^(VSSVirgilCard *aliceCard, NSError *error) {
		VSSEmailIdentity *aliceIdentity = [virgil.identities
			createEmailIdentityWithEmail:aliceCard.identity];

	// initiate an identity verification process.
	[aliceIdentity checkWithOptions:nil completion:^(NSError *error) {
		[aliceIdentity confirmWithConfirmationCode:@"[CONFIRMATION_CODE]"
			completion:^(NSError *error) {
				[virgil.cards revokeEmailCard:aliceCard identity:aliceIdentity
					ownerKey: aliceKey completion:^(NSError *error) {
				//...
			}];
		}];
	}];
}];
```