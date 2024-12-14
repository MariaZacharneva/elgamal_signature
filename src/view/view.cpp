//
// Created by Masha on 2024-12-09.
//

#include "view.h"

#include <iostream>
#include <qboxlayout.h>
#include <QPushButton>

View::View() {
    sign_view_ = new SignView(this);
    verify_view_ = new VerifyView(this);
    auto* allBox = new QHBoxLayout(this);
    allBox->addWidget(sign_view_);
    allBox->addWidget(verify_view_);
    setLayout(allBox);
    setWindowTitle("ElGamal signature");
    setWindowIcon(QIcon(tr(":images/icon.png")));
}

void View::CopySignature() {
    StringSignature signature = sign_view_->GetSignature();
    verify_view_->SetSignature(signature);
}
