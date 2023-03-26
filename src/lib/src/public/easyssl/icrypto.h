/*
 * Copyright (C) 2021-2023 QuasarApp.
 * Distributed under the lgplv3 software license, see the accompanying
 * Everyone is permitted to copy and distribute verbatim copies
 * of this license document, but changing it is not allowed.
*/


#ifndef I_CRYPTO_H
#define I_CRYPTO_H

#include "global.h"
#include <QByteArray>

namespace EasySSL {

/**
 * @brief The ICrypto class This is base interface that provide encription functionality.
 */
class EASYSSL_EXPORT ICrypto
{

public:

    /**
     * @brief The Features enum this is list of the supported ecription features
     */
    enum Features {
        /// Signin and check sign of the data.
        Signing = 0x01,
        /// Encription and decription data
        Encription = 0x02
    };

    /**
     * @brief makeKeys This method generate the public and private keys of the ECDSA.
     * @param pubKey This is result public key.
     * @param privKey This is result private key.
     * @return true if keys generated successful.
     */
    virtual bool makeKeys(QByteArray &pubKey, QByteArray &privKey) const = 0;

    /**
     * @brief supportedFeatures This method should return supported featurs of the current encription alhorithm
     * @return Features list.
     * @see Features
     */
    virtual Features supportedFeatures() const = 0;

    /**
     * @brief decrypt This method decript @a message using @a key.
     * @param message This is encripted message that should be decripted.
     * @param key This is key that will be used for decription for the @a message.
     * @return decripted message or empty string if method not supported or decripted failed.
     * @see IAsyncEncription::encript
     */
    virtual QByteArray decrypt(const QByteArray& message, const QByteArray& key) = 0;
    /**
     * @brief encrypt This method encript @a message using @a key.
     * @param message This is a message that should be decripted.
     * @param key This is key that will be used for encription for the @a message.
     * @return decripted message or empty string if method not supported or decripted failed.
     * @see IAsyncEncription::encript
     */
    virtual QByteArray encrypt(const QByteArray& message, const QByteArray& key) = 0;

    /**
     * @brief signMessage This method should be sign the @a message using the @a key.
     * @param message This is input data that should be signed.
     * @param key This is a privete key for encription the @a message.
     * @return signature data array.
     * @see AsyncKeysAuth::descrupt
     */
    virtual QByteArray signMessage(const QByteArray& message, const QByteArray& key) const = 0;

    /**
     * @brief checkSign This method should be check signature of the @a message using the @a key.
     * @param message This is input data that should be decripted.
     * @param signature This is signature that will be checked for the @a message.
     * @param key This is a public key for encription the @a inpputData.
     * @return decripted data array.
     * @see AsyncKeysAuth::encrypt
     */
    virtual bool checkSign(const QByteArray& message,
                           const QByteArray& signature,
                           const QByteArray& key) const = 0;
};

}
#endif // I_CRYPTO_H
