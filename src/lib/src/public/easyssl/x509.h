//#
//# Copyright (C) 2021-2023 QuasarApp.
//# Distributed under the GPLv3 software license, see the accompanying
//# Everyone is permitted to copy and distribute verbatim copies
//# of this license document, but changing it is not allowed.
//#

#ifndef X509_H
#define X509_H

#include "global.h"
#include "icertificate.h"
#include "icrypto.h"

namespace EasySSL {

/**
 * @brief The X509 class This is wrapper of the ssl objects.
 */
class EASYSSL_EXPORT X509: public ICertificate
{
public:
    X509(const QSharedPointer<ICrypto>& generator);

    // ICertificate interface
public:
    SelfSignedSertificate create(const SslSrtData& certificateData) const override;
};

}
#endif // X509_H
