/*
 * Copyright (C) 2021-2023 QuasarApp.
 * Distributed under the GPLv3 software license, see the accompanying
 * Everyone is permitted to copy and distribute verbatim copies
 * of this license document, but changing it is not allowed.
*/

#ifndef ICERTIFICATE_H
#define ICERTIFICATE_H

#include <QSslCertificate>
#include <QSslKey>
#include "easyssl/icrypto.h"
#include "global.h"
#include <QByteArray>

namespace EasySSL {

/**
 * @brief The SslSrtData struct This structure contains base information for generate self signed ssl certefication.
 */
struct SslSrtData {
    QString country = "BY";
    QString organization = "QuasarApp";
    QString commonName = "";
    long long endTime = 31536000L; //1 year
};

/**
 * @brief The SelfSignedSertificate struct contains qt certificate object and private key of them.
 */
struct EASYSSL_EXPORT SelfSignedSertificate {
    SelfSignedSertificate(){}
    SelfSignedSertificate(const SelfSignedSertificate & other)  {
        crt = other.crt;
        key = other.key;
    };
    QSslCertificate crt;
    QSslKey key;
};

/**
 * @brief The ICertificate class is base interface for all certificate generators classes.
 *
 */
class EASYSSL_EXPORT ICertificate
{
public:

    ICertificate(const QSharedPointer<ICrypto>& generator);

    /**
     * @brief create This method create a self signed certificate.
     * @param certificateData This input extra data of certificate.
     * @return certificate data with private key.
     */
    virtual SelfSignedSertificate create(const SslSrtData& certificateData) const = 0;

protected:
    /**
     * @brief generator This method return private key generator.
     * @return private key generator.
     */
    const QSharedPointer<ICrypto>& keyGenerator() const;

private:
    QSharedPointer<ICrypto> _keyGenerator;
};

}
#endif // ICERTIFICATE_H
