//#
//# Copyright (C) 2020-2023 QuasarApp.
//# Distributed under the lgplv3 software license, see the accompanying
//# Everyone is permitted to copy and distribute verbatim copies
//# of this license document, but changing it is not allowed.
//#


#include "authtest.h"
#include <easyssl/authecdsa.h>
#include <thread>

/*
 * test class
 */
class ECDSA: public EasySSL::AuthECDSA {

public:

    // AsyncKeysAuth interface
    void setPrivateKey(const QByteArray &newPriv) {
        _priv = newPriv;
    }

    QByteArray getPrivateKey() const {
        return _priv;
    };

private:
    QByteArray _priv;

};


AuthTest::AuthTest() {}

AuthTest::~AuthTest() {}

void AuthTest::test() {
    // create a publick and private keys array.
    QByteArray pub, priv;
    QString userID;

    // create test auth object using ecdsa algorithm
    ECDSA edsa;

    // make public and private keys.
    QVERIFY(edsa.makeKeys(pub, priv));
    edsa.setPrivateKey(priv);
    edsa.setPublicKey(pub);

    // make user id
    QString userIDOfPubKey = QCryptographicHash::hash(pub,
                                                      QCryptographicHash::Sha256).
                             toBase64(QByteArray::Base64UrlEncoding);

    // check createed keys. should be larget then 0.
    QVERIFY(pub.length() && priv.length());

    // The terst object should be invalid because it is not prepared.
    QVERIFY(!edsa.isValid());

    // the authetication should be failed bacause ecdsa class is invalid.
    QVERIFY(!edsa.auth(600, &userID));
    QVERIFY(userID.isEmpty());

    // prepare an authentication object.
    QVERIFY(edsa.prepare());
    // the prepared object should be valid.
    QVERIFY(edsa.isValid());

    // authentication should be finished successful because auth object contains prepared valid signature.
    QVERIFY(edsa.auth(600, &userID));
    QVERIFY(userID == userIDOfPubKey);

    // forget user id before new auth
    userID.clear();

    // authentication should be failed because the time range is depricated.
    QVERIFY(!edsa.auth(0, &userID));
    QVERIFY(userID.isEmpty());

    // change subsribe time and try login.
    edsa.setUnixTime(time(0) + 1);

    std::this_thread::sleep_for(std::chrono::seconds(1));

    // should be failed because signature is different of the time.
    QVERIFY(!edsa.auth(600, &userID));
    QVERIFY(userID.isEmpty());


}
