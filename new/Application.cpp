#include "Application.hpp"
#include "MainWindow.hpp"
#include "Storage.hpp"

wxIMPLEMENT_APP(Application);
//wxIMPLEMENT_APP_CONSOLE(Application);

Application::Application() {
    storage=NULL;
}

bool Application::OnInit() {
    if(!wxApp::OnInit())
        return false;

    storage=new Storage("/home/tobias/pmate_copy2.pmate", false);


    new MainWindow();
    return true;
}

int Application::OnExit() {
    return wxApp::OnExit();
}
