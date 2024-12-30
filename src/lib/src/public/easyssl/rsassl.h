//#
//# Copyright (C) 2021-2025 QuasarApp.
//# Distributed under the GPLv3 software license, see the accompanying
//# Everyone is permitted to copy and distribute verbatim copies
//# of this license document, but changing it is not allowed.
//#


#ifndef RSASSL30_H
#define RSASSL30_H

#include "global.h"
#include "icrypto.h"

namespace EasySSL {

/**
 * @brief The RSASSL class This is wrapper for RSA algorithm of openssl 3.0 libraryry.
 */
class EASYSSL_EXPORT RSASSL: public EasySSL::ICrypto
{
    /**
     * @brief The RsaPadding enum
     * @see https://www.openssl.org/docs/man1.1.1/man3/RSA_public_encrypt.html
     */
    enum RSAPadding {

        /// Raw RSA encryption. This mode should only be used to implement cryptographically sound padding modes in the application code. Encrypting user data directly with RSA is insecure.
        NO_PADDING,

        /// EME-OAEP as defined in PKCS #1 v2.0 with SHA-1, MGF1 and an empty encoding parameter. This mode is recommended for all new applications.
        PKCS1_OAEP_PADDING,

        ///PKCS #1 v1.5 padding. This currently is the most widely used mode. However, it is highly recommended to use RSA_PKCS1_OAEP_PADDING in new applications. SEE WARNING BELOW.
        PKCS1_PADDING,
    };

    enum RSABits {
        RSA_Base = 1024,
        RSA_2048 = 2 * RSA_Base,
        RSA_3072 = 3 * RSA_Base,
        RSA_4096 = 4 * RSA_Base,

    };

public:
    RSASSL(RSAPadding padding = PKCS1_OAEP_PADDING);

    void *makeRawKeys() const override;
    Features supportedFeatures() const override;
    QSsl::KeyAlgorithm keyAlgorithm() const override;

    QByteArray signMessage(const QByteArray &inputData, const QByteArray &key) const override;
    bool checkSign(const QByteArray &inputData, const QByteArray &signature, const QByteArray &key) const override;

    /**
     * @brief decrypt This method has empty implementation.
     * @return empty array.
     */
    QByteArray decrypt(const QByteArray &message, const QByteArray &key) override;

    /**
     * @brief encrypt This method has empty implementation.
     * @return empty array.
     */
    QByteArray encrypt(const QByteArray &message, const QByteArray &key) override;

    /**
     * @brief padding This is mode of pending data before icnription.
     * @return encryption pending mode.
     */
    RSAPadding padding() const;

    /**
     * @brief setPadding This method sets new mode for encryption pendong.
     * @param newPadding This is new new mode.
     * @note You must change padding mode for both side (encryption and decryption)
    */
    void setPadding(RSAPadding newPadding);

    /**
     * @brief bits return cuurrent rsa keys size mode. Using oly for generate keys.
     * @return size of the rsa keys.
     */
    RSABits bits() const;

    /**
     * @brief setBits sets new value of the rsa key generator.
     * @param newBits this is new value of the key size of rsa.
     */
    void setBits(RSABits newBits);

private:
    int getRawOpenSSLPandingValue(RSAPadding panding);
    int getPandingSize(RSAPadding panding);

    RSAPadding _padding = PKCS1_OAEP_PADDING;
    RSABits _bits = RSABits::RSA_3072;

};

}
#endif // RSASSL30_H
