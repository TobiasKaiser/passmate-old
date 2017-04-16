#pragma once
#include <wx/wx.h>

class Application : public wxApp {
    public:
        Application();

        virtual bool OnInit();
        virtual int OnExit();
        
};

wxDECLARE_APP(Application); // this defines wxGetApp