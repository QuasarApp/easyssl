//#
//# Copyright (C) 2021-2023 QuasarApp.
//# Distributed under the GPLv3 software license, see the accompanying
//# Everyone is permitted to copy and distribute verbatim copies
//# of this license document, but changing it is not allowed.
//#


#ifndef RSASSL11_H
#define RSASSL11_H

#include "global.h"
#include "icrypto.h"

namespace EasySSL {

/**
 * @brief The RSASSL11 class This is wrapper of the openssl 1.1 implementation of the RSA alghorithm
 */
class EASYSSL_EXPORT RSASSL11: public EasySSL::ICrypto
{
public:
    RSASSL11();

    bool makeKeys(QByteArray &pubKey, QByteArray &privKey) const override;
    Features supportedFeatures() const override;


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
#endif // RSASSL11_H
