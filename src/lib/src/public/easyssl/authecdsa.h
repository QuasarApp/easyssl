//#
//# Copyright (C) 2021-2024 QuasarApp.
//# Distributed under the GPLv3 software license, see the accompanying
//# Everyone is permitted to copy and distribute verbatim copies
//# of this license document, but changing it is not allowed.
//#


#ifndef AUTHECDSA_H
#define AUTHECDSA_H

#include "ecdsassl.h"
#include "asynckeysauth.h"

namespace EasySSL {

/**
 * @brief The AuthECDSA class is ecdsa implementation of the Async authentication. This implementation based on Openssl library.
 */
typedef AsyncKeysAuth<ECDSASSL> AuthECDSA;

}

#endif // AUTHECDSA_H
