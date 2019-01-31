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

#include "MainWindowCrypton.h"
#include "ui_MainWindowCrypton.h"

MainWindowCrypton::MainWindowCrypton(QWidget *parent) : QMainWindow(parent), ui(new Ui::MainWindowCrypton)
{
    ui->setupUi(this);
    setWindowFlags(Qt::Window | Qt::MSWindowsFixedSizeDialogHint);
}

MainWindowCrypton::~MainWindowCrypton()
{
    delete ui;
}

void MainWindowCrypton::on_pushButton_clicked()
{
    Text = ui->lineEdit->text();
    if (Text == "")
    {
        QMessageBox::information(nullptr, "Information", "Enter Password");
        return;
    }
    String[0] = Text.toLocal8Bit();
    Text = ui->lineEdit_2->text();
    if (Text == "")
    {
        QMessageBox::information(nullptr, "Information", "Add file");
        return;
    }
    String[1] = Text.toLocal8Bit();
    Text = ui->lineEdit_3->text();
    if (Text == "")
    {
        QMessageBox::information(nullptr, "Information", "Save the encrypted file");
        return;
    }
    String[2] = Text.toLocal8Bit();
    if (String[0].size() > 55)
    {
        QMessageBox::information(nullptr, "Information", "Maximum password size exceeded");
        return;
    }
    if (String[1] == String[2])
    {
        QMessageBox::information(nullptr, "Information", "Error, identical file names");
        return;
    }
    ui->pushButton->setEnabled(false);
    ui->pushButton_2->setEnabled(false);
    ui->pushButton_3->setEnabled(false);
    ui->toolButton->setEnabled(false);
    ui->toolButton_2->setEnabled(false);
    ui->toolButton_3->setEnabled(false);
    Thread = new QThread;
    ThreadEnCryp = new ThreadCrypt(String);
    ThreadEnCryp->moveToThread(Thread);
    connect(Thread, SIGNAL(started()), ThreadEnCryp, SLOT(RunEnCrypt()));
    connect(ThreadEnCryp, SIGNAL(SendProgressCount(int)), this, SLOT(ResiveProgressCount(int)), Qt::AutoConnection);
    connect(ThreadEnCryp, SIGNAL(SendMessage(int)), this, SLOT(ResiveMessage(int)), Qt::AutoConnection);
    Thread->start();
}

void MainWindowCrypton::on_pushButton_2_clicked()
{
    Text = ui->lineEdit->text();
    if (Text == "")
    {
        QMessageBox::information(nullptr, "Information", "Enter Password");
        return;
    }
    String[0] = Text.toLocal8Bit();
    Text = ui->lineEdit_2->text();
    if (Text == "")
    {
        QMessageBox::information(nullptr, "Information", "Add file");
        return;
    }
    String[1] = Text.toLocal8Bit();
    Text = ui->lineEdit_4->text();
    if (Text == "")
    {
        QMessageBox::information(nullptr, "Information", "Add a directory to save the decrypted file");
        return;
    }
    String[2] = Text.toLocal8Bit();
    if (String[0].size() > 55)
    {
        QMessageBox::information(nullptr, "Information", "Maximum password size exceeded");
        return;
    }
    ui->pushButton->setEnabled(false);
    ui->pushButton_2->setEnabled(false);
    ui->pushButton_3->setEnabled(false);
    ui->toolButton->setEnabled(false);
    ui->toolButton_2->setEnabled(false);
    ui->toolButton_3->setEnabled(false);
    Thread = new QThread;
    ThreadDeCryp = new ThreadCrypt(String);
    ThreadDeCryp->moveToThread(Thread);
    connect(Thread, SIGNAL(started()), ThreadDeCryp, SLOT(RunDeCrypt()));
    connect(ThreadDeCryp, SIGNAL(SendProgressCount(int)), this, SLOT(ResiveProgressCount(int)), Qt::AutoConnection);
    connect(ThreadDeCryp, SIGNAL(SendMessage(int)), this, SLOT(ResiveMessage(int)), Qt::AutoConnection);
    Thread->start();
}

void MainWindowCrypton::on_toolButton_clicked()
{
    File = new QFileDialog;
    Text = File->getOpenFileName();
    ui->lineEdit_2->setText(Text);
    delete File;
    File = nullptr;
}

void MainWindowCrypton::on_toolButton_2_clicked()
{
    File = new QFileDialog;
    Text = File->getSaveFileName();
    ui->lineEdit_3->setText(Text);
    delete File;
    File = nullptr;
}

void MainWindowCrypton::on_toolButton_3_clicked()
{
    File = new QFileDialog;
    Text = File->getExistingDirectory();
    ui->lineEdit_4->setText(Text);
    delete File;
    File = nullptr;
}

void MainWindowCrypton::ResiveProgressCount(int count)
{
    ui->progressBar->setValue(count);
}

void MainWindowCrypton::ResiveMessage(int mode)
{
    switch (mode)
    {
    case 0:
        QMessageBox::information(nullptr, "Information", "Encryption Complete");
        delete ThreadEnCryp;
        ThreadEnCryp = nullptr;
        break;
    case 1:
        QMessageBox::information(nullptr, "Information", "Decryption Complete");
        delete ThreadDeCryp;
        ThreadDeCryp = nullptr;
        break;
    case 2:
        QMessageBox::information(nullptr, "Information", "Password not entered correctly or the file is not encrypted by the CryptoSecurity program");
        delete ThreadDeCryp;
        ThreadDeCryp = nullptr;
        break;
    }
    ui->progressBar->setValue(0);
    Thread->terminate();
    delete Thread;
    Thread = nullptr;
    ui->pushButton->setEnabled(true);
    ui->pushButton_2->setEnabled(true);
    ui->pushButton_3->setEnabled(true);
    ui->toolButton->setEnabled(true);
    ui->toolButton_2->setEnabled(true);
    ui->toolButton_3->setEnabled(true);
}

void MainWindowCrypton::on_pushButton_3_clicked()
{
    QDesktopServices::openUrl(QUrl::fromLocalFile("COPYING.txt"));
    QMessageBox::information(nullptr, "Information",
    "CRYPTOSECURITY version 1.0. File Encryption Software\n"
    "Copyright (C) 2018  Maxim Shershavikov\n\n"
    "This program is free software: you can redistribute it and/or modify\n"
    "it under the terms of the GNU General Public License as published by\n"
    "the Free Software Foundation, either version 3 of the License, or\n"
    "(at your option) any later version.\n\n"
    "This program is distributed in the hope that it will be useful,\n"
    "but WITHOUT ANY WARRANTY; without even the implied warranty of\n"
    "MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the\n"
    "GNU General Public License for more details.\n\n"
    "You should have received a copy of the GNU General Public License\n"
    "along with this program.  If not, see <https://www.gnu.org/licenses/>.\n\n"
    "Email m.shershavikov@yandex.ru\n"
    "To read a copy of the GNU General Public License in a file COPYING.txt,\n"
    "to do this, click the AbautProgram button.");
}
