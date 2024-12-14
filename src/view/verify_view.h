//
// Created by Masha on 2024-12-09.
//

#ifndef VERIFY_VIEW_H
#define VERIFY_VIEW_H
#include <QMainWindow>
#include <QPushButton>
#include <QTextEdit>
#include <QLineEdit>
#include <QDialog>

#include "abstract_view.h"
#include "../cryptography/cryptography.h"
#include "../cryptography/signature.h"


class VerifyView : public QWidget {
    Q_OBJECT

public:
    explicit VerifyView(AbstractView* parent);
    void SetSignature(StringSignature s);

private:
    void HandleCopy();
    void HandleVerify();

    QWidget* CreateKeyLayout();
    QWidget* CreateMessageLayout();

    QPushButton* verify_;
    QPushButton* copy_;

    QTextEdit* message_text_edit_;
    QLineEdit* prime_edit_;
    QLineEdit* generator_edit_;
    QLineEdit* public_key_edit_;
    QLineEdit* signature_r_edit_;
    QLineEdit* signature_s_edit_;

    QWidget* result_widget_;

    AbstractView* parent_ = nullptr;
};


#endif //VERIFY_VIEW_H
