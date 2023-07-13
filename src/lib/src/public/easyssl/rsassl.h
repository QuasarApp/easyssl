//#
//# Copyright (C) 2021-2023 QuasarApp.
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
 * @brief The RSASSL30 class This is wrapper for RSA algorithm of openssl 3.0 libraryry.
 */
class EASYSSL_EXPORT RSASSL: public EasySSL::ICrypto
{
public:
    RSASSL();

    EVP_PKEY *makeRawKeys() const override;
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

};

}
#endif // RSASSL30_H
