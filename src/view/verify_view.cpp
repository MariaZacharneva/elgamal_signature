//
// Created by Masha on 2024-12-09.
//

#include "verify_view.h"

#include <iostream>
#include <QGridLayout>
#include <QGroupBox>
#include <QLabel>
#include <QFormLayout>
#include <QPainter>

#include "../cryptography/tools.h"

VerifyView::VerifyView(AbstractView* parent) : parent_(parent) {
    prime_edit_ = new QLineEdit;
    generator_edit_ = new QLineEdit;
    public_key_edit_ = new QLineEdit;
    signature_r_edit_ = new QLineEdit;
    signature_s_edit_ = new QLineEdit;
    message_text_edit_ = new QTextEdit;

    message_text_edit_->setPlaceholderText(tr("Your message"));

    copy_ = new QPushButton(tr("Copy data"));
    connect(copy_, &QPushButton::pressed, this, &VerifyView::HandleCopy);

    verify_ = new QPushButton(tr("Verify"));
    connect(verify_, &QPushButton::pressed, this, &VerifyView::HandleVerify);

    result_widget_ = new QWidget;
    result_widget_->setStyleSheet("background-color:gray;");
    result_widget_->setMinimumHeight(20);

    auto header = new QLabel(tr("VERIFY"));
    header->setStyleSheet("font:18pt;");
    header->setAlignment(Qt::AlignCenter);

    auto* mainLayout = new QVBoxLayout;
    mainLayout->addWidget(header, 0);
    mainLayout->addWidget(CreateKeyLayout(), 1);
    mainLayout->addWidget(CreateMessageLayout(), 1);
    setLayout(mainLayout);
}

void VerifyView::SetSignature(StringSignature s) {
    prime_edit_->setText(tr(s.prime.c_str()));
    generator_edit_->setText(tr(s.generator.c_str()));
    public_key_edit_->setText(tr(s.public_key.c_str()));
    signature_s_edit_->setText(tr(s.signature_s.c_str()));
    signature_r_edit_->setText(tr(s.signature_r.c_str()));
    message_text_edit_->setText(tr(s.message.c_str()));
}

void VerifyView::HandleCopy() {
    result_widget_->setStyleSheet("background-color:gray;");
    if (parent_ == nullptr) {
        std::cout << "Cannot handle copy: parent is nullptr" << std::endl;
        return;
    }
    parent_->CopySignature();
}

void VerifyView::HandleVerify() {
    Signature signature = {
        StringToUint128(prime_edit_->text().toStdString()),
        StringToUint128(generator_edit_->text().toStdString()),
        StringToUint128(public_key_edit_->text().toStdString()),
        StringToUint128(signature_r_edit_->text().toStdString()),
        StringToUint128(signature_s_edit_->text().toStdString()),
    };
    bool verified = ElGamal::Verify(
        message_text_edit_->toPlainText().toStdString(), signature);
    if (verified) {
        log("Verified, result: true");
        result_widget_->setStyleSheet("background-color:#19a337;");
    } else {
        log("Verified, result: false");
        result_widget_->setStyleSheet("background-color:#d01111;");
    }
}

QWidget* VerifyView::CreateKeyLayout() {
    auto formGroupBox = new QGroupBox(tr("Public key"));
    auto* layout = new QFormLayout;
    layout->addRow(copy_);
    layout->addRow(new QLabel(tr("Prime number:")), prime_edit_);
    layout->addRow(new QLabel(tr("Generator:")), generator_edit_);
    layout->addRow(new QLabel(tr("Public key:")), public_key_edit_);
    formGroupBox->setLayout(layout);
    return formGroupBox;
}

QWidget* VerifyView::CreateMessageLayout() {
    auto* gridGroupBox = new QGroupBox(tr("Message"));
    auto* grid_layout = new QGridLayout;
    grid_layout->addWidget(message_text_edit_, 0, 0, 4, 1);
    grid_layout->addWidget(new QLabel(tr("R =")), 0, 1);
    grid_layout->addWidget(signature_r_edit_, 0, 2);
    grid_layout->addWidget(new QLabel(tr("S =")), 1, 1);
    grid_layout->addWidget(signature_s_edit_, 1, 2);
    grid_layout->addWidget(verify_, 5, 0, 1, 3);
    grid_layout->addWidget(result_widget_, 3, 2);
    gridGroupBox->setLayout(grid_layout);
    return gridGroupBox;
}
