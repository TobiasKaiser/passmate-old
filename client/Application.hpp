#pragma once

#include <string>

#include <wx/wx.h>

class SyncableStorage;

class Application : public wxApp {
    public:
        Application();
		~Application();

        virtual bool OnInit();
        virtual int OnExit();

        SyncableStorage &GetStorage() {
        	if(storage) {
        		return *storage;
 			} else {
 				throw std::runtime_error("No Storage object found.");
 			}
        }

    protected:
        SyncableStorage *storage;
        std::string storage_filename;
};

wxDECLARE_APP(Application); // this defines wxGetApp