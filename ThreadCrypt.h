/**********************************************************************************

    CRYPTOSECURITY version 1.0. File Encryption Software
    Copyright (C) 2018  Maxim Shershavikov

    This file is part of CryptoSecurity v1.0.

    CryptoSecurity v1.0 is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    CryptoSecurity v1.0 is distributed in the hope that it will be useful,
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
#include <cstdio>
#include <io.h>
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
    void SendMessage(int mode);
private:
    HASHMD5        *HashMd5;
    CRYPTOSECURITY *CryptoSecurity;
    EXPANSEKEY     *ExpanseKey;
    ENCRYPT        *EnCrypt;
    DECRYPT        *DeCrypt;
    FILE           *CreateFile;
    FILE           *OpenFile;
    long long      *PtrSizeFile;
    QByteArray     Str[3];
    BYTE           CryptoKey[16];
    BYTE           Data[16];
    BYTE           HeadStart[16];
    BYTE           HeadNext[16];
    long double    count;
    long double    sizecount;
    long long      SizeFile;
    long long      SzFl;
    void _cykleByte(BYTE *PtrOwn, BYTE *PtrTwo, int i);
    void _cykleByteZero(BYTE *Ptr, int i);
    void _nameOfFile(int i);
    void _searchNameOfFile(int n);
    void _progressCount(FILE *OpenFile);
};

#endif // TREADENCRYPT_H
