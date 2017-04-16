#include "Application.hpp"
#include "MainWindow.hpp"
//wxIMPLEMENT_APP(Application);
wxIMPLEMENT_APP_CONSOLE(Application);

Application::Application() {

}

bool Application::OnInit() {
    if(!wxApp::OnInit())
        return false;
    
    new MainWindow();
    return true;
}

int Application::OnExit() {
    return wxApp::OnExit();
}
