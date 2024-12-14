//
// Created by Masha on 2024-12-09.
//

#ifndef SIGN_VIEW_H
#define SIGN_VIEW_H
#include <QLineEdit>
#include <QMainWindow>
#include <QPushButton>
#include <QTextEdit>
#include <QTextBlock>

#include "abstract_view.h"
#include "../cryptography/cryptography.h"
#include "../cryptography/signature.h"


class SignView : public QWidget {
    Q_OBJECT

public:
    explicit SignView(AbstractView* parent);
    StringSignature GetSignature() const;

private:
    void HandleGenerate();
    void HandleSign();
    void HandleGeneratePublicKey();

    void UpdateElGamal();
    void ClearSignature();

    QWidget* CreateKeyLayout();
    QWidget* CreateMessageLayout();

    ElGamal el_gamal_;

    QPushButton* sign_button_;
    QPushButton* generate_button_;
    QPushButton* generate_public_key_button_;

    QTextEdit* message_text_edit_;
    QLineEdit* prime_edit_;
    QLineEdit* generator_edit_;
    QLineEdit* private_key_edit_;
    QLineEdit* public_key_edit_;
    QLineEdit* signature_r_edit_;
    QLineEdit* signature_s_edit_;

    AbstractView* parent_ = nullptr;
};


#endif //SIGN_VIEW_H
