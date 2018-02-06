//
//  CardManager+Queries.swift
//  VirgilSDK
//
//  Created by Eugen Pivovarov on 1/19/18.
//  Copyright © 2018 VirgilSecurity. All rights reserved.
//

import Foundation
import VirgilCryptoAPI

public extension CardManager {
    func getCard(withId cardId: String) -> CallbackOperation<Card> {
        let operation = CallbackOperation<Card> {
            let token = try self.getToken(operation: "FIXME")

            let rawSignedModel = try self.cardClient.getCard(withId: cardId, token: token.stringRepresentation())
            guard let card = Card.parse(crypto: self.crypto, rawSignedModel: rawSignedModel) else {
                throw CardManagerError.cardParsingFailed
            }

            try self.verifyCard(card)

            return card
        }

        return operation
    }

    func publishCard(rawCard: RawSignedModel) -> CallbackOperation<Card> {
        let operation = CallbackOperation<Card> {
            let token = try self.getToken(operation: "FIXME")

            let rawSignedModel = try self.cardClient.publishCard(model: rawCard, token: token.stringRepresentation())
            guard let card = Card.parse(crypto: self.crypto, rawSignedModel: rawSignedModel) else {
                throw CardManagerError.cardParsingFailed
            }

            try self.verifyCard(card)

            return card
        }

        return operation
    }

    func publishCard(privateKey: PrivateKey, publicKey: PublicKey, identity: String, previousCardId: String? = nil,
                     extraFields: [String: String]? = nil) throws -> CallbackOperation<Card> {

        let rawCard = try self.generateRawCard(privateKey: privateKey, publicKey: publicKey,
                                               identity: identity, previousCardId: previousCardId,
                                               extraFields: extraFields)

        return self.publishCard(rawCard: rawCard)
    }

    func searchCards(identity: String) -> CallbackOperation<[Card]> {
        let operation = CallbackOperation<[Card]> {
            let token = try self.getToken(operation: "FIXME")
            let tokenString = token.stringRepresentation()

            let rawSignedModels = try self.cardClient.searchCards(identity: identity, token: tokenString)

            var cards: [Card] = []
            for rawSignedModel in rawSignedModels {
                guard let card = Card.parse(crypto: self.crypto, rawSignedModel: rawSignedModel) else {
                    throw CardManagerError.cardParsingFailed
                }
                cards.append(card)
            }

            cards.forEach { card in
                let previousCard = cards.first(where: { $0.identifier == card.previousCardId })
                card.previousCard = previousCard
                previousCard?.isOutdated = true
            }
            let result = cards.filter { card in cards.filter { $0.previousCard == card }.isEmpty }

            return result
        }

        return operation
    }
}

//objc compatable Queries
public extension CardManager {
    @objc func getCard(withId cardId: String, completion: @escaping (Card?, Error?) -> ()) {
        self.getCard(withId: cardId).start { result in
            switch result {
            case .success(let card):
                completion(card, nil)
            case .failure(let error):
                completion(nil, error)
            }
        }
    }

    @objc func publishCard(rawCard: RawSignedModel, timeout: NSNumber? = nil,
                           completion: @escaping (Card?, Error?) -> ()) {
        self.publishCard(rawCard: rawCard).start { result in
            switch result {
            case .success(let card):
                completion(card, nil)
            case .failure(let error):
                completion(nil, error)
            }
        }
    }

    @objc func publishCard(privateKey: PrivateKey, publicKey: PublicKey, identity: String,
                           previousCardId: String? = nil, extraFields: [String: String]? = nil,
                           completion: @escaping (Card?, Error?) -> ()) {
        do {
            try self.publishCard(privateKey: privateKey, publicKey: publicKey, identity: identity,
                                 previousCardId: previousCardId, extraFields: extraFields)
            .start { result in
                switch result {
                case .success(let card):
                    completion(card, nil)
                case .failure(let error):
                    completion(nil, error)
                }
            }
        } catch {
            completion(nil, error)
        }
    }

    @objc func searchCards(identity: String, completion: @escaping ([Card]?, Error?) -> ()) {
        self.searchCards(identity: identity).start { result in
            switch result {
            case .success(let cards):
                completion(cards, nil)
            case .failure(let error):
                completion(nil, error)
            }
        }
    }
}
