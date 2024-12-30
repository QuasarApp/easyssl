//#
//# Copyright (C) 2020-2025 QuasarApp.
//# Distributed under the GPLv3 software license, see the accompanying
//# Everyone is permitted to copy and distribute verbatim copies
//# of this license document, but changing it is not allowed.
//#


#ifndef AUTH_TEST_H
#define AUTH_TEST_H
#include "test.h"
#include "testutils.h"

#include <QtTest>

class AuthTest: public Test, protected TestUtils
{
public:
    AuthTest();
    ~AuthTest();

    void test();

};

#endif // AUTH_TEST_H
