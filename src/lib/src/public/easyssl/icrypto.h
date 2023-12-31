/*
 * Copyright (C) 2021-2024 QuasarApp.
 * Distributed under the GPLv3 software license, see the accompanying
 * Everyone is permitted to copy and distribute verbatim copies
 * of this license document, but changing it is not allowed.
*/


#ifndef I_CRYPTO_H
#define I_CRYPTO_H

#include "global.h"
#include "qssl.h"
#include <QByteArray>

namespace EasySSL {

/**
* @brief The ICrypto class, This is base interface that provide encryption functionality.
 */
class EASYSSL_EXPORT ICrypto
{

public:

    /**
     * @brief The Features enum this is list of the supported description features
     */
    enum Features {
        /// Signin and check sign of the data.
        Signing = 0x01,
        /// Encryption and decryption data
        Encryption = 0x02
    };

    /**
     * @brief makeKeys This method generate the public and private keys of the ECDSA.
     * @param pubKey This is result public key.
     * @param privKey This is result private key.
     * @return true if keys generated successful.
     */
    bool makeKeys(QByteArray &pubKey, QByteArray &privKey) const;

    /**
     * @brief keyAlgorithm This method should be return Qt Key algorithm (needed for generate cetrificates.)
     * @return
     */
    virtual QSsl::KeyAlgorithm keyAlgorithm() const = 0;

    /**
     * @brief supportedFeatures This method should return supported featurs of the current encryption algorithm
     * @return Features list.
     * @see Features
     */
    virtual Features supportedFeatures() const = 0;

    /**
     * @brief decrypt This method decrypt @a message using @a key.
     * @param message This is encrypted message that should be decrypted.
     * @param key This is key that will be used for decryption for the @a message.
     * @return decrypted message or empty string if method not supported or decrypted failed.
     * @see IAsyncEncryption::encrypt
     */
    virtual QByteArray decrypt(const QByteArray& message, const QByteArray& key) = 0;

    /**
     * @brief encrypt This method encrypt @a message using @a key.
     * @param message This is a message that should be decrypted.
     * @param key This is key that will be used for encryption for the @a message.
     * @return decrypted message or empty string if method not supported or decrypted failed.
     * @see IAsyncEncryption::encrypt
     */
    virtual QByteArray encrypt(const QByteArray& message, const QByteArray& key) = 0;

    /**
     * @brief signMessage This method should be sign the @a message using the @a key.
     * @param message This is input data that should be signed.
     * @param key This is a privete key for encryption the @a message.
     * @return signature data array.
     * @see AsyncKeysAuth::descrupt
     */
    virtual QByteArray signMessage(const QByteArray& message, const QByteArray& key) const = 0;

    /**
     * @brief checkSign This method should be check signature of the @a message using the @a key.
     * @param message This is input data that should be decrypted.
     * @param signature This is signature that will be checked for the @a message.
     * @param key This is a public key for encryption the @a inpputData.
     * @return decrypted data array.
     * @see AsyncKeysAuth::encrypt
     */
    virtual bool checkSign(const QByteArray& message,
                           const QByteArray& signature,
                           const QByteArray& key) const = 0;

    /**
     * @brief makeKeys This method generate the public and private keys of the ECDSA.
     * @return pointer to generated keys. This method must return EVP_PKEY* structure.
     */
    virtual void * makeRawKeys() const = 0;
};

}
#endif // I_CRYPTO_H
