#pragma once
#include <wx/wx.h>


class Storage;

class Application : public wxApp {
    public:
        Application();

        virtual bool OnInit();
        virtual int OnExit();

        Storage &GetStorage() {
        	if(storage) {
        		return *storage;
 			} else {
 				throw std::runtime_error("No Storage object found.");
 			}
        }

    protected:
        Storage *storage;
};

wxDECLARE_APP(Application); // this defines wxGetApp