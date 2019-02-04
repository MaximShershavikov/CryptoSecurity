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

#include "ThreadCrypt.h"

ThreadCrypt::ThreadCrypt(QByteArray *String, QObject *parent) :    
    QObject        (parent),
    HashMd5        (nullptr),
    CryptoSecurity (nullptr),
    ExpanseKey     (nullptr),
    EnCrypt        (nullptr),
    DeCrypt        (nullptr),
    FileCreate     (nullptr),
    OpenFile       (nullptr),
    Memory         (nullptr),
    Buffer         (nullptr),
    ptr            (nullptr),
    count          { 0 },
    SizeFile       { 0 },
    HeadStart      { 0 },
    HeadNext       { 0 },
    SizeFreeMemory ( 0 )
{
    strcpy(HeadStart, "Crypset+=+163rsd");
    strcpy(HeadNext, "Crypset+=3fkveql");
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
    FileCreate = nullptr;
    OpenFile = nullptr;
    delete Memory;
    Memory = nullptr;
    delete[] Buffer;
    Buffer = nullptr;
    ptr = nullptr;
    count[0] = 0;
    count[1] = 0;
    SizeFile[0] = 0;
    SizeFile[1] = 0;
    SizeFreeMemory = 0;
}

void ThreadCrypt::RunEnCrypt()
{
    HashMd5 = new HASHMD5(Str[0].data());
    CryptoSecurity =  new CRYPTOSECURITY();
    ExpanseKey = new EXPANSEKEY(HashMd5->Md5Hash);
    EnCrypt = new ENCRYPT();

    OpenFile = fopen(Str[1], "rb");
    FileCreate = fopen(Str[2], "wb");

    Memory = new MEMORYSTATUSEX;
    Memory->dwLength = sizeof(*Memory);
    GlobalMemoryStatusEx(Memory);
    if (Memory->ullAvailPhys >= 100000000)
        SizeFreeMemory = 30000000;
    else MessageProvade(3);
    if (Memory->ullAvailPhys >= 300000000)
        SizeFreeMemory = 100000000;
    if (Memory->ullAvailPhys >= 500000000)
        SizeFreeMemory = 150000000;
    if (Memory->ullAvailPhys >= 1000000000)
        SizeFreeMemory = 250000000;
    if (Memory->ullAvailPhys >= 1500000000)
        SizeFreeMemory = 400000000;

    Buffer = new BYTE[SizeFreeMemory];
    ptr = Buffer;

    EnCrypt->CryptRound(ExpanseKey->ExKey, reinterpret_cast<BYTE*>(HeadStart));
    memcpy(ptr, HeadStart, sizeof(HeadStart));
    ptr += 16;

    _nameOfFile((Str[1].size()) - 1);
    ptr += 16;
    EnCrypt->CryptRound(ExpanseKey->ExKey, reinterpret_cast<BYTE*>(HeadNext));
    memcpy(ptr, HeadNext, sizeof(HeadNext));
    ptr += 16;

    SizeFile[0] = filelength(fileno(OpenFile));
    SizeFile[1] = SizeFile[0];
    count[0] = 100.0L / (SizeFile[0] / 16);
    memcpy(ptr, SizeFile, sizeof(SizeFile));
    EnCrypt->CryptRound(ExpanseKey->ExKey, ptr);

    ptr += 16;
    SizeFreeMemory -= static_cast<unsigned long long>(ptr - Buffer);

metka_1:
    if (SizeFile[0] <= static_cast<long long>(SizeFreeMemory))
        fread(ptr, static_cast<size_t>(SizeFile[0]), 1, OpenFile);
    else
        fread(ptr, static_cast<size_t>(SizeFreeMemory), 1, OpenFile);
    SizeFile[1] = 0;
    while (SizeFile[1] < SizeFile[0] &&
           SizeFile[1] < static_cast<long long>(SizeFreeMemory))
    {
        EnCrypt->CryptRound(ExpanseKey->ExKey, ptr);
        ptr += 16;
        SizeFile[1] += 16;
        count[1] += count[0];
        emit SendProgressCount(static_cast<int>(count[1]));
    }
    fwrite(Buffer, static_cast<size_t>(ptr - Buffer), 1, FileCreate);
    if (SizeFile[0] > static_cast<long long>(SizeFreeMemory))
    {
        SizeFile[0] -= SizeFile[1];
        SizeFreeMemory = static_cast<unsigned long long>(ptr - Buffer);
        ptr = Buffer;
        goto metka_1;
    }

    emit SendProgressCount(100);
    fclose(OpenFile);
    fclose(FileCreate);
    MessageProvade(0);
}

void ThreadCrypt::RunDeCrypt()
{
    HashMd5 = new HASHMD5(Str[0].data());
    CryptoSecurity =  new CRYPTOSECURITY();
    ExpanseKey = new EXPANSEKEY(HashMd5->Md5Hash);
    DeCrypt = new DECRYPT();

    OpenFile = fopen(Str[1], "rb");

    Memory = new MEMORYSTATUSEX;
    Memory->dwLength = sizeof(*Memory);
    GlobalMemoryStatusEx(Memory);
    if (Memory->ullAvailPhys >= 100000000)
        SizeFreeMemory = 30000000;
    else MessageProvade(4);
    if (Memory->ullAvailPhys >= 300000000)
        SizeFreeMemory = 100000000;
    if (Memory->ullAvailPhys >= 500000000)
        SizeFreeMemory = 150000000;
    if (Memory->ullAvailPhys >= 1000000000)
        SizeFreeMemory = 250000000;
    if (Memory->ullAvailPhys >= 1500000000)
        SizeFreeMemory = 400000000;

    Buffer = new BYTE[SizeFreeMemory];
    ptr = Buffer;

    SizeFile[0] = filelength(fileno(OpenFile));
    if (SizeFile[0] <= static_cast<long long>(SizeFreeMemory))
        fread(ptr, static_cast<size_t>(SizeFile[0]), 1, OpenFile);
    else
        fread(ptr, static_cast<size_t>(SizeFreeMemory), 1, OpenFile);

    DeCrypt->DeCryptRound(ExpanseKey->ExKey, ptr);
    for (int i = 0; i < 16; i++)
    {
        if (ptr[i] != HeadStart[i])
        {
            emit MessageProvade(2);
            return;
        }
    }
    ptr += 16;
    Str[2] += '/';
    _searchNameOfFile(0);
    ptr += 16;

    DeCrypt->DeCryptRound(ExpanseKey->ExKey, ptr);
    memcpy(&SizeFile[0], ptr, sizeof(SizeFile[0]));
    count[0] = 100.0L / (SizeFile[0] / 16);

    ptr += 16;
    SizeFreeMemory -= static_cast<unsigned long long>(ptr - Buffer);
    FileCreate = fopen(Str[2], "wb");

metka_2:
    SizeFile[1] = 0;
    while (SizeFile[1] < SizeFile[0] &&
           SizeFile[1] < static_cast<long long>(SizeFreeMemory))
    {
        DeCrypt->DeCryptRound(ExpanseKey->ExKey, ptr);
        ptr += 16;
        SizeFile[1] += 16;
        count[1] += count[0];
        emit SendProgressCount(static_cast<int>(count[1]));
    }
    ptr -= SizeFile[1];
    if (SizeFile[1] >= SizeFile[0])
        fwrite(ptr, static_cast<size_t>(SizeFile[0]), 1, FileCreate);
    else
    {
        fwrite(ptr, static_cast<size_t>(SizeFreeMemory), 1, FileCreate);
        SizeFile[0] -= SizeFile[1];
        SizeFreeMemory = static_cast<unsigned long long>((ptr - Buffer) + SizeFile[1]);
        ptr = Buffer;
        fread(Buffer, static_cast<size_t>(SizeFreeMemory), 1, OpenFile);
        goto metka_2;
    }

    emit SendProgressCount(100);
    fclose(OpenFile);
    fclose(FileCreate);
    MessageProvade(1);
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
                ptr[j] = static_cast<BYTE>(Str[1].data()[i]);
                i++;
            }
            if (i >= Str[1].size())
            {
                if (j <= 14) ptr[j + 1] = 0;
                else
                {
                    EnCrypt->CryptRound(ExpanseKey->ExKey, ptr);
                    break;
                }
            }
            if (j == 15)
            {
                EnCrypt->CryptRound(ExpanseKey->ExKey, ptr);
                ptr += 16;
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
        DeCrypt->DeCryptRound(ExpanseKey->ExKey, ptr);
        for (int j = 0; j < 16; j++)
        {
            if (ptr[j] != HeadNext[j])
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
            Str[2] += static_cast<char>(ptr[j]);
        }
        ptr += 16;
        n = 0;
        break;
    case 2:
        return;
    }
    _searchNameOfFile(n);
}
