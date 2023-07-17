//#
//# Copyright (C) 2020-2023 QuasarApp.
//# Distributed under the GPLv3 software license, see the accompanying
//# Everyone is permitted to copy and distribute verbatim copies
//# of this license document, but changing it is not allowed.
//#

#include <QtTest>
#include "cryptotest.h"
#include "authtest.h"
#include "crttest.h"
#include "easyssl/rsassl.h"
#include <easyssl/ecdsassl.h>


// Use This macros for initialize your own test classes.
// Check exampletests
#define TestCase(name, testClass) \
    void name() { \
        initTest(new testClass()); \
    }

using CrtTestX509RSA = CrtTest<EasySSL::X509, EasySSL::RSASSL>;
using CrtTestX509ECDSA = CrtTest<EasySSL::X509, EasySSL::ECDSASSL>;

/**
 * @brief The tstMain class - this is main test class
 */
class tstMain : public QObject
{
    Q_OBJECT


public:
    tstMain();

    ~tstMain();

private slots:

    // BEGIN TESTS CASES
    TestCase(authTest, AuthTest)
    TestCase(cryptoTestESDSA, CryptoTest<EasySSL::ECDSASSL>)
    TestCase(cryptoTestRSA, CryptoTest<EasySSL::RSASSL>)
    TestCase(crtTestX509RSA, CrtTestX509RSA)
    TestCase(crtTestX509ECDSA, CrtTestX509ECDSA)

    // END TEST CASES

private:

    /**
     * @brief initTest This method prepare @a test for run in the QApplication loop.
     * @param test are input test case class.
     */
    void initTest(Test* test);

    QCoreApplication *_app = nullptr;
};

/**
 * @brief tstMain::tstMain
 * init all availabel units for testsing
 */
tstMain::tstMain() {

    // init xample unit test
    int argc =0;
    char * argv[] = {nullptr};

    _app = new QCoreApplication(argc, argv);
    QCoreApplication::setApplicationName("testeasyssl");
    QCoreApplication::setOrganizationName("QuasarApp");

    auto path = QStandardPaths::writableLocation(QStandardPaths::AppDataLocation);

    QDir(path).removeRecursively();

}

tstMain::~tstMain() {
    _app->exit(0);
    delete _app;
}

void tstMain::initTest(Test *test) {
    QTimer::singleShot(0, this, [this, test]() {
        test->test();
        delete test;
        _app->exit(0);
    });

    _app->exec();
}

QTEST_APPLESS_MAIN(tstMain)

#include "tstMain.moc"
