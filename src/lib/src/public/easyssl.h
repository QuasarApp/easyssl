//#
//# Copyright (C) 2021-2025 QuasarApp.
//# Distributed under the GPLv3 software license, see the accompanying
//# Everyone is permitted to copy and distribute verbatim copies
//# of this license document, but changing it is not allowed.
//#

#include "easyssl/global.h"
#include <QString>


namespace EasySSL {

/**
 * @brief init main initialize method of The easyssl library
 * @return true if library initialized successfull
 */
bool EASYSSL_EXPORT init();

/**
 * @brief version This method return string value of a library version
 * @return string value of a library version
 */
QString EASYSSL_EXPORT version();

};
