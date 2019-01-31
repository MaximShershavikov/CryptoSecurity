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

#ifndef MAINWINDOWCRYPTON_H
#define MAINWINDOWCRYPTON_H

#include <QMainWindow>
#include <QMessageBox>
#include <QFileDialog>
#include <QThread>
#include <QDesktopServices>
#include "ThreadCrypt.h"

namespace Ui
{
    class MainWindowCrypton;
}

class MainWindowCrypton : public QMainWindow
{
    Q_OBJECT
public:
    explicit MainWindowCrypton(QWidget *parent = nullptr);
    ~MainWindowCrypton();
private slots:
    void on_pushButton_clicked();
    void on_pushButton_2_clicked();
    void on_toolButton_clicked();
    void on_toolButton_2_clicked();
    void ResiveProgressCount(int);
    void ResiveMessage(int mode);
    void on_toolButton_3_clicked();
    void on_pushButton_3_clicked();
private:
    Ui::MainWindowCrypton *ui;
    QFileDialog           *File;
    QThread               *Thread;
    ThreadCrypt           *ThreadEnCryp;
    ThreadCrypt           *ThreadDeCryp;
    QString               Text;
    QByteArray            String[3];
};

#endif // MAINWINDOWCRYPTON_H
