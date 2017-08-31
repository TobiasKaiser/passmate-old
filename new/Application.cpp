#include <string>

#include <wx/msgdlg.h>

#include "Application.hpp"
#include "MainWindow.hpp"
#include "Storage.hpp"



using namespace std;

wxIMPLEMENT_APP(Application);
//wxIMPLEMENT_APP_CONSOLE(Application);

Application::Application() {
    storage=NULL;
    storage_filename = "/home/tobias/workspace/passmate/new/test.pmate";
}

bool Application::OnInit() {
    if(!wxApp::OnInit()) {
        return false;
    }

 	try {
    	storage=new Storage(storage_filename);
    } catch(const Storage::Exception &stex) {
		wxMessageDialog errDialog(NULL, wxString("Error: "+ string(stex.what())), wxT("Error"), wxOK|wxCENTRE);
		errDialog.ShowModal();
  
   		return false; // If an exception in the constructor happens, we have to exit after showing the error.
   	}

    if(!storage->FileExists()) {
    	// Setup new password storage

    	wxPasswordEntryDialog passwordDialog1(NULL, wxT("No password storage found yet. Enter passphrase to creat new storage:"));
    	wxPasswordEntryDialog passwordDialog2(NULL, wxT("Repeat passphrase:"));
		
		bool passwordsMatching;
    	do {
    		passwordDialog1.SetValue(wxString(""));
    		passwordDialog2.SetValue(wxString(""));
			if(passwordDialog1.ShowModal() != wxID_OK) {
		    	return false;
		    }
		    if(passwordDialog2.ShowModal() != wxID_OK) {
		    	return false;
		    }
		    passwordsMatching=string(passwordDialog1.GetValue()) == string(passwordDialog2.GetValue());
		    if(!passwordsMatching) {
		    	wxMessageDialog errDialog(NULL, wxString("You entered two different passphrases. Please try again."), wxT("Error"), wxOK|wxCENTRE);
				errDialog.ShowModal();
		    }

    	} while (!passwordsMatching);

    	try {
	   		storage->Open(true, string(passwordDialog1.GetValue()));
	   	} catch(const Storage::Exception &stex) {
			wxMessageDialog errDialog(NULL, wxString("Error: "+ string(stex.what())), wxT("Error"), wxOK|wxCENTRE);
			errDialog.ShowModal();

			return false;
	   	}


    } else {
		wxPasswordEntryDialog passwordDialog(NULL, wxT("Enter passphrase to unlock password storage:"));

    	do {
	    	// Open existing password sotrage
		    passwordDialog.SetValue("");
		    if(passwordDialog.ShowModal() != wxID_OK) {
		    	return false;
		    }

		    try {
		   		storage->Open(false, string(passwordDialog.GetValue()));
		   	} catch(const Storage::Exception &stex) {
				wxMessageDialog errDialog(NULL, wxString("Error: "+ string(stex.what())), wxT("Error"), wxOK|wxCENTRE);
				errDialog.ShowModal();
		  
		  		if(stex.getErrCode() != Storage::Exception::WRONG_PASSPHRASE) {
		  			return false;
		  		}
		   	}
		} while(!storage->IsValid());
	}

    new MainWindow();
    return true;
}

int Application::OnExit() {
    return wxApp::OnExit();
}
