/**********************************************************************************

    CRYPTOSECURITY version 1.1. File Encryption Software
    Copyright (C) 2019  Maxim Shershavikov

    This file is part of CryptoSecurity v1.1.

    CryptoSecurity v1.1 is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    CryptoSecurity v1.1 is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.

    Email m.shershavikov@yandex.ru
    To read a copy of the GNU General Public License in a file COPYING.txt,
    to do this, click the AbautProgram button.

**********************************************************************************/

#ifndef TREADENCRYPT_H
#define TREADENCRYPT_H

#include <QObject>
#include <QThread>
#include <io.h>
#include <Windows.h>
#include "CryptoSecurity.h"
#include "HashMd5.h"
#include "ExpanseKey.h"
#include "EnCrypt.h"
#include "DeCrypt.h"

class ThreadCrypt : public QObject
{
    Q_OBJECT
public:
    explicit ThreadCrypt(QByteArray *String, QObject *parent = nullptr);
    ~ThreadCrypt();
public slots:
    void RunEnCrypt();
    void RunDeCrypt();
signals:
    void SendProgressCount(int);
    void MessageProvade(int mode);
private:
    HASHMD5             *HashMd5;
    CRYPTOSECURITY      *CryptoSecurity;
    EXPANSEKEY          *ExpanseKey;
    ENCRYPT             *EnCrypt;
    DECRYPT             *DeCrypt;
    FILE                *FileCreate;
    FILE                *OpenFile;
    MEMORYSTATUSEX      *Memory;
    BYTE                *Buffer;
    BYTE                *ptr;
    QByteArray          Str[3];
    long double         count[2];
    long long           SizeFile[2];
    char                HeadStart[16];
    char                HeadNext[16];
    unsigned long long  SizeFreeMemory;
protected:
    void _nameOfFile(int i);
    void _searchNameOfFile(int n);
};

#endif // TREADENCRYPT_H
