//#
//# Copyright (C) 2020-2023 QuasarApp.
//# Distributed under the GPLv3 software license, see the accompanying
//# Everyone is permitted to copy and distribute verbatim copies
//# of this license document, but changing it is not allowed.
//#


#ifndef CRYPTO_TEST_H
#define CRYPTO_TEST_H

#include "test.h"
#include "testutils.h"
#include <QtTest>
#include <easyssl/icrypto.h>

template <class TestClass>
class CryptoTest: public Test, protected TestUtils
{
public:

    void test() override {
        // test short messges
        testImpl("Test");

        //test long messages

        const int Mb = 1024 * 1024 * 1024; //1 mb
        testImpl(QByteArray(Mb, 'c'));

    } ;


    void testImpl(const QByteArray& message) const {
        // create a publick and private keys array.
        QByteArray pub, priv;
        TestClass crypto;

        QVERIFY2(crypto.makeKeys(pub, priv), "Failed to generate keys pair.");
        QVERIFY2(pub.size(), "Publick key should be generated successfull");
        QVERIFY2(priv.size(), "Private key should be generated successfull");

        if (crypto.supportedFeatures() & EasySSL::ICrypto::Features::Signing) {
            auto siganture = crypto.signMessage(message, priv);
            QVERIFY2(siganture.size(), "Siganture of the message should not be empty");
            QVERIFY2(crypto.checkSign(message, siganture, pub), "failed to check message");
        }

        if (crypto.supportedFeatures() & EasySSL::ICrypto::Features::Encription) {
            auto encriptedMsg = crypto.encrypt(message, pub);
            QVERIFY2(encriptedMsg.size(), "Encripted message should not be empty");
            auto decryptedMsg = crypto.decrypt(encriptedMsg, priv);
            QVERIFY2(decryptedMsg == message, "Failed to check message after decryption");
        }
    }
};

#endif // CRYPTO_TEST_H
