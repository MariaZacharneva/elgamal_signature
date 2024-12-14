//
// Created by Masha on 2024-12-09.
//

#include "sign_view.h"

#include <iostream>
#include <QFormLayout>
#include <QGroupBox>
#include <QGridLayout>
#include <QLabel>

#include "../cryptography/tools.h"

SignView::SignView(AbstractView* parent) : parent_(parent) {
    prime_edit_ = new QLineEdit;
    generator_edit_ = new QLineEdit;
    private_key_edit_ = new QLineEdit;
    public_key_edit_ = new QLineEdit;
    signature_r_edit_ = new QLineEdit;
    signature_s_edit_ = new QLineEdit;
    message_text_edit_ = new QTextEdit;

    public_key_edit_->setEnabled(false);
    signature_r_edit_->setEnabled(false);
    signature_s_edit_->setEnabled(false);
    message_text_edit_->setPlaceholderText(tr("Your message"));

    generate_button_ = new QPushButton(tr("Generate key"));
    connect(generate_button_, &QPushButton::pressed, this,
            &SignView::HandleGenerate);

    sign_button_ = new QPushButton(tr("Sign"));
    connect(sign_button_, &QPushButton::pressed, this, &SignView::HandleSign);

    generate_public_key_button_ = new QPushButton(tr("Generate public key"));
    connect(generate_public_key_button_, &QPushButton::pressed, this,
            &SignView::HandleGeneratePublicKey);

    auto header = new QLabel(tr("SIGN"));
    header->setStyleSheet("font:18pt;");
    header->setAlignment(Qt::AlignCenter);

    auto* mainLayout = new QVBoxLayout;
    mainLayout->addWidget(header, 0);
    mainLayout->addWidget(CreateKeyLayout(), 1);
    mainLayout->addWidget(CreateMessageLayout(), 1);
    setLayout(mainLayout);
}

StringSignature SignView::GetSignature() const {
    StringSignature signature;
    signature.prime = prime_edit_->text().toStdString();
    signature.generator = generator_edit_->text().toStdString();
    signature.public_key = public_key_edit_->text().toStdString();
    signature.signature_r = signature_r_edit_->text().toStdString();
    signature.signature_s = signature_s_edit_->text().toStdString();
    signature.message = message_text_edit_->toPlainText().toStdString();
    return signature;
}

void SignView::HandleGenerate() {
    ClearSignature();

    prime_edit_->setText(to_string(el_gamal_.GeneratePrime()).c_str());
    generator_edit_->setText(to_string(el_gamal_.GenerateGenerator()).c_str());
    auto keys = el_gamal_.GeneratePublicKey();
    private_key_edit_->setText(to_string(keys.first).c_str());
    public_key_edit_->setText(to_string(keys.second).c_str());
}

void SignView::HandleGeneratePublicKey() {
    ClearSignature();
    UpdateElGamal();

    auto public_key = el_gamal_.GeneratePublicKey(
        StringToUint128(private_key_edit_->text().toStdString())).second;
    public_key_edit_->setText(to_string(public_key).c_str());
}

void SignView::HandleSign() {
    UpdateElGamal();

    auto signature = el_gamal_.Sign(
        message_text_edit_->toPlainText().toStdString());
    signature_r_edit_->setText(to_string(signature.first).c_str());
    signature_s_edit_->setText(to_string(signature.second).c_str());
}

void SignView::UpdateElGamal() {
    el_gamal_.SetPrime(StringToUint128(prime_edit_->text().toStdString()));
    el_gamal_.SetGenerator(
        StringToUint128(generator_edit_->text().toStdString()));
}

void SignView::ClearSignature() {
    signature_s_edit_->clear();
    signature_r_edit_->clear();
}

QWidget* SignView::CreateKeyLayout() {
    auto* layout1 = new QHBoxLayout;
    layout1->addWidget(new QLabel(tr("Prime:")));
    layout1->addWidget(prime_edit_);
    layout1->addWidget(new QLabel(tr("Generator:")));
    layout1->addWidget(generator_edit_);

    auto* layout2 = new QHBoxLayout;
    layout2->addWidget(new QLabel(tr("Private key:")));
    layout2->addWidget(private_key_edit_);
    layout2->addWidget(generate_public_key_button_);

    auto* layout3 = new QHBoxLayout;
    layout3->addWidget(new QLabel(tr("Public key:")));
    layout3->addWidget(public_key_edit_);

    auto formGroupBox = new QGroupBox(tr("Public key"));
    auto* layout = new QFormLayout;
    layout->addWidget(generate_button_);
    layout->addRow(layout1);
    layout->addRow(layout2);
    layout->addRow(layout3);
    formGroupBox->setLayout(layout);
    return formGroupBox;
}

QWidget* SignView::CreateMessageLayout() {
    auto* gridGroupBox = new QGroupBox(tr("Message"));
    auto* grid_layout = new QGridLayout;
    grid_layout->addWidget(message_text_edit_, 0, 0, 3, 1);
    grid_layout->addWidget(new QLabel(tr("R =")), 0, 1);
    grid_layout->addWidget(signature_r_edit_, 0, 2);
    grid_layout->addWidget(new QLabel(tr("S =")), 1, 1);
    grid_layout->addWidget(signature_s_edit_, 1, 2);
    grid_layout->addWidget(sign_button_, 5, 0, 1, 3);
    gridGroupBox->setLayout(grid_layout);
    return gridGroupBox;
}
