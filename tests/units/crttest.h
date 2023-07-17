//#
//# Copyright (C) 2020-2023 QuasarApp.
//# Distributed under the GPLv3 software license, see the accompanying
//# Everyone is permitted to copy and distribute verbatim copies
//# of this license document, but changing it is not allowed.
//#


#ifndef CRTTEST_H
#define CRTTEST_H

#include "qtestcase.h"
#include "test.h"
#include "testutils.h"
#include <easyssl/icertificate.h>
#include <easyssl/x509.h>


/**
 * @brief The CrtTest class is bse test class for the testin all certificate generators
 * @tparam CrtGenerator This any class inheret of ICertificate interface.
 *
 * @example
 * @code{cpp}
 *  #include "x509.h"
 *  #include "CrtTest"
 *
 *  TestCase(cryptoTestRSA, CrtTest<EasySSL::x509, EasySSL::RSASSL>)
 * @endcode
 */
template <class CrtGenerator, class Algorithm>
class CrtTest: public Test, protected TestUtils
{
public:
    CrtTest() = default;
    void test() override {

        CrtGenerator gen(QSharedPointer<Algorithm>::create());
        EasySSL::SslSrtData data;

        auto crt = gen.create(data);
        QVERIFY2(!crt.crt.isNull(), "Failed to generate certificate.");
        QVERIFY2(!crt.key.isNull(), "Failed to generate private key for certificate.");

    }
};

#endif // CRTTEST_H
