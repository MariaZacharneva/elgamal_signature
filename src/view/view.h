//
// Created by Masha on 2024-12-09.
//

#ifndef VIEW_H
#define VIEW_H
#include <QMainWindow>

#include "abstract_view.h"
#include "sign_view.h"
#include "verify_view.h"


class View : public AbstractView {
    Q_OBJECT

public:
    explicit View();
    void CopySignature() override;

private:
    SignView* sign_view_;
    VerifyView* verify_view_;
};


#endif //VIEW_H
