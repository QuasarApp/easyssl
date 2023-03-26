//#
//# Copyright (C) 2021-2023 QuasarApp.
//# Distributed under the GPLv3 software license, see the accompanying
//# Everyone is permitted to copy and distribute verbatim copies
//# of this license document, but changing it is not allowed.
//#


#ifndef QH_ECDSA_SSL_1_1_H
#define QH_ECDSA_SSL_1_1_H

#include "global.h"
#include "icrypto.h"

namespace EasySSL {

/**
 * @brief The ECDSASSL11 class is ecdsa implementation of the Async authentication. This implementation based on Openssl library.
 * @note This class compatibility only with ssl 1.1 and ssl 3.0 (depricated fundtions).
 */
class EASYSSL_EXPORT ECDSASSL11: public EasySSL::ICrypto
{

public:
    ECDSASSL11();
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

#endif // QH_ECDSA_SSL_1_1_H
