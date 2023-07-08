/*
 * Copyright (C) 2021-2023 QuasarApp.
 * Distributed under the GPLv3 software license, see the accompanying
 * Everyone is permitted to copy and distribute verbatim copies
 * of this license document, but changing it is not allowed.
*/



#include "icertificate.h"


namespace EasySSL {

ICertificate::ICertificate(const QSharedPointer<ICrypto> &generator) {
    _keyGenerator = generator;
}

const QSharedPointer<ICrypto> &ICertificate::keyGenerator() const {
    return _keyGenerator;
}

}
