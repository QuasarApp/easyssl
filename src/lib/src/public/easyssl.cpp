//#
//# Copyright (C) 2021-2023 QuasarApp.
//# Distributed under the GPLv3 software license, see the accompanying
//# Everyone is permitted to copy and distribute verbatim copies
//# of this license document, but changing it is not allowed.
//#

#include "easyssl.h"

namespace EasySSL {

bool init() {
    initeasysslResources();
    return true;
}

QString version() {
    return EASYSSL_VERSION;
}


}
