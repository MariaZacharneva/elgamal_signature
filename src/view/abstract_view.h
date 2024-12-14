//
// Created by Masha on 2024-12-11.
//

#ifndef ABSTRACT_VIEW_H
#define ABSTRACT_VIEW_H
#include <qwidget.h>

class AbstractView : public QWidget {
    Q_OBJECT

public:
    virtual void CopySignature() = 0;
};

#endif //ABSTRACT_VIEW_H
