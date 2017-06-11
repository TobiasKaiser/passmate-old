#pragma once
#include <wx/wx.h>


class Storage;

class Application : public wxApp {
    public:
        Application();

        virtual bool OnInit();
        virtual int OnExit();

    protected:
        Storage *storage;
};

wxDECLARE_APP(Application); // this defines wxGetApp