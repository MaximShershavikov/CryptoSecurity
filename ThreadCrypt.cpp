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

#include "ThreadCrypt.h"

ThreadCrypt::ThreadCrypt(QByteArray *String, QObject *parent) :
    QObject(parent),
    HashMd5(nullptr),
    CryptoSecurity(nullptr),
    ExpanseKey(nullptr),
    EnCrypt(nullptr),
    DeCrypt(nullptr),
    CreateFile(nullptr),
    OpenFile(nullptr),
    PtrSizeFile(nullptr),
    CryptoKey{ 0 },
    Data{ 0 },
    HeadStart{ 'C','r','y','p','s','e','t','+','=','+','1','6','3','r','s','d' },
    HeadNext{ 'C','r','y','p','s','e','t','+','=','3','f','k','v','e','q','l' },
    count(0),
    sizecount(0),
    SizeFile(0),
    SzFl(0)

{
    Str[0] = String[0];
    Str[1] = String[1];
    Str[2] = String[2];
}

ThreadCrypt::~ThreadCrypt()
{
    delete HashMd5;
    HashMd5 = nullptr;
    delete ExpanseKey;
    ExpanseKey = nullptr;
    delete EnCrypt;
    EnCrypt = nullptr;
    delete DeCrypt;
    DeCrypt = nullptr;
    delete CryptoSecurity;
    CryptoSecurity = nullptr;
    PtrSizeFile = nullptr;
    count = 0;
    sizecount = 0;
    SizeFile = 0;
    SzFl = 0;
}

void ThreadCrypt::_cykleByte(BYTE *PtrOwn, BYTE *PtrTwo, int i)
{
    if (i < 16)
    {
        PtrOwn[i] = PtrTwo[i];
        _cykleByte(PtrOwn, PtrTwo, ++i);
    }
    else return;
}

void ThreadCrypt::_cykleByteZero(BYTE *Ptr, int i)
{
    if (i < 16)
    {
        Ptr[i] = 0;
        _cykleByteZero(Ptr, ++i);
    }
    else return;
}

void ThreadCrypt::_nameOfFile(int i)
{
    if (Str[1].data()[i] == '/')
    {
        i++;
        for (int j = 0; j < 16; j++)
        {
            if (i < Str[1].size())
            {
                Data[j] = static_cast<BYTE>(Str[1].data()[i]);
                i++;
            }
            if (i >= Str[1].size())
            {
                if (j <= 14) Data[j + 1] = 0;
                else
                {
                    EnCrypt->CryptRound(ExpanseKey->ExKey, Data);
                    fwrite(Data, sizeof(Data), 1, CreateFile);
                    break;
                }
            }
            if (j == 15)
            {
                EnCrypt->CryptRound(ExpanseKey->ExKey, Data);
                fwrite(Data, sizeof(Data), 1, CreateFile);
                j = -1;
            }
        }
        return;
    }
    i--;
    _nameOfFile(i);
}

void ThreadCrypt::_searchNameOfFile(int n)
{
    switch (n)
    {
    case 0:
        fread(Data, sizeof(Data), 1, OpenFile);
        DeCrypt->DeCryptRound(ExpanseKey->ExKey, Data);
        count += sizecount;
        for (int j = 0; j < 16; j++)
        {
            if (Data[j] != HeadNext[j])
            {
                n = 1;
                break;
            }
            else n = 2;
        }
        break;
    case 1:
        for (int j = 0; j < 16; j++)
        {
            Str[2] += static_cast<char>(Data[j]);
        }
        n = 0;
        break;
    case 2:
        return;
    }
    _searchNameOfFile(n);
}

void ThreadCrypt::_progressCount(FILE *OpenFile)
{
    fseek(OpenFile, sizeof(OpenFile), SEEK_END);
    sizecount = 100.0L / (ftell(OpenFile) / 16);
    fseek(OpenFile, 0, SEEK_SET);
}

void ThreadCrypt::RunEnCrypt()
{
    HashMd5 = new HASHMD5(Str[0].data());
    _cykleByte(CryptoKey, HashMd5->Md5Hash, 0);
    CryptoSecurity =  new CRYPTOSECURITY();
    ExpanseKey = new EXPANSEKEY(CryptoKey);
    EnCrypt = new ENCRYPT();
    CreateFile = fopen(Str[2], "wb");
    OpenFile = fopen(Str[1], "rb");
    EnCrypt->CryptRound(ExpanseKey->ExKey, HeadStart);
    fwrite(HeadStart, sizeof(HeadStart), 1, CreateFile);
    _nameOfFile((Str[1].size()) - 1);
    EnCrypt->CryptRound(ExpanseKey->ExKey, HeadNext);
    fwrite(HeadNext, sizeof(HeadNext), 1, CreateFile);
    fseek(OpenFile, sizeof(OpenFile), SEEK_END);
    _cykleByteZero(Data, 0);
    SizeFile = filelength(fileno(OpenFile));
    PtrSizeFile = &SizeFile;
    mempcpy(Data, PtrSizeFile, sizeof(SizeFile));
    EnCrypt->CryptRound(ExpanseKey->ExKey, Data);
    fwrite(Data, sizeof(Data), 1, CreateFile);
    _progressCount(OpenFile);
    while (!feof(OpenFile))
    {
        _cykleByteZero(Data, 0);
        fread(Data, sizeof(Data), 1, OpenFile);
        EnCrypt->CryptRound(ExpanseKey->ExKey, Data);
        fwrite(Data, sizeof(Data), 1, CreateFile);
        count += sizecount;
        emit SendProgressCount(static_cast<int>(count));
    }
    fclose(CreateFile);
    fclose(OpenFile);
    _cykleByteZero(Data, 0);
    _cykleByteZero(CryptoKey, 0);
    emit SendMessage(0);
}

void ThreadCrypt::RunDeCrypt()
{
    HashMd5 = new HASHMD5(Str[0].data());
    _cykleByte(CryptoKey, HashMd5->Md5Hash, 0);
    CryptoSecurity =  new CRYPTOSECURITY();
    ExpanseKey = new EXPANSEKEY(CryptoKey);
    DeCrypt = new DECRYPT();
    OpenFile = fopen(Str[1], "rb");
    _progressCount(OpenFile);
    fread(Data, sizeof(Data), 1, OpenFile);
    DeCrypt->DeCryptRound(ExpanseKey->ExKey, Data);
    count += sizecount;
    for (int i = 0; i < 16; i++)
    {
        if (Data[i] != HeadStart[i])
        {
            emit SendMessage(2);
            return;
        }
    }
    Str[2] += '/';
    _searchNameOfFile(0);
    fread(Data, sizeof(Data), 1, OpenFile);
    DeCrypt->DeCryptRound(ExpanseKey->ExKey, Data);
    PtrSizeFile = reinterpret_cast<long long*>(Data);
    SizeFile = *PtrSizeFile;
    CreateFile = fopen(Str[2], "wb");
    while (!feof(OpenFile))
    {
        _cykleByteZero(Data, 0);
        fread(Data, sizeof(Data), 1, OpenFile);
        count += sizecount;
        emit SendProgressCount(static_cast<int>(count));
        if (SzFl == SizeFile)
        {
            emit SendProgressCount(static_cast<int>(100));
            continue;
        }
        SzFl += 16;
        if (SzFl > SizeFile)
        {
            emit SendProgressCount(static_cast<int>(100));
            DeCrypt->DeCryptRound(ExpanseKey->ExKey, Data);
            fwrite(Data, 16 - (static_cast<size_t>(SzFl - SizeFile)), 1, CreateFile);
            SzFl = SizeFile;
            continue;
        }
        DeCrypt->DeCryptRound(ExpanseKey->ExKey, Data);
        fwrite(Data, sizeof(Data), 1, CreateFile);
    }
    fclose(OpenFile);
    fclose(CreateFile);
    _cykleByteZero(Data, 0);
    _cykleByteZero(CryptoKey, 0);
    emit SendMessage(1);
}
