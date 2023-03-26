//#
//# Copyright (C) 2021-2023 QuasarApp.
//# Distributed under the lgplv3 software license, see the accompanying
//# Everyone is permitted to copy and distribute verbatim copies
//# of this license document, but changing it is not allowed.
//#

#include "easyssl/global.h"
#include <QString>

inline void initeasysslResources() { Q_INIT_RESOURCE(easyssl); }

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
