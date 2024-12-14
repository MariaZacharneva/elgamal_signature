#include <QApplication>
#include <QPushButton>
#include <QSettings>

#include "src/view/view.h"

int main(int argc, char *argv[]) {
    QApplication app (argc, argv);
    auto* view = new View;
    view->show();
    return app.exec();
}
