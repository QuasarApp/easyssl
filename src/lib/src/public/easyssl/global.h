//#
//# Copyright (C) 2018-2023 QuasarApp.
//# Distributed under the GPLv3 software license, see the accompanying
//# Everyone is permitted to copy and distribute verbatim copies
//# of this license document, but changing it is not allowed.
//#

#ifndef EASYSSL_GLOBAL_H
#define EASYSSL_GLOBAL_H

#include <QtCore/qglobal.h>

#define EASYSSL_VERSION "0.2.a2c421a"

#if defined(EASYSSL_LIBRARY)
#  define EASYSSL_EXPORT Q_DECL_EXPORT
#else
#  define EASYSSL_EXPORT Q_DECL_IMPORT
#endif

#endif //EASYSSL_GLOBAL_H

