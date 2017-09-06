#include <string>
#include <cstdlib>

#include <wx/msgdlg.h>

#include "cxxopts.hpp"

#include "Application.hpp"
#include "MainWindow.hpp"
#include "SyncableStorage.hpp"



using namespace std;

wxIMPLEMENT_APP(Application);
//wxIMPLEMENT_APP_CONSOLE(Application);

Application::Application() {
    storage=NULL;


    storage_filename = "";
}

bool Application::OnInit() {
    //if(!wxApp::OnInit()) {
    //    return false;
    //}


	cxxopts::Options options("passmate", "passmate -- Password manager");
	options.positional_help("[optional args]");

	options.add_options()
  		//("d,debug", "Enable debugging")
  		("h,help" , "Print help")
  		("dry-run", "Do not commit any changes to storage")
  		("p,paranoid-backup", "Create a backup of storage file every time it changes")
  		("f,storage-filename", "Storage filename", cxxopts::value<std::string>());


	char **myArgv = argv;

	try {
		options.parse(argc, myArgv);
	} catch (const cxxopts::OptionException& e) {
		cout << "error parsing options: " << e.what() << std::endl;
		return false;
	}

	if (options.count("help")) {
		cout << options.help({"", "Group"}) << std::endl;
		return false;
	}

	if(options.count("dry-run")) {
 		// TODO
	}

	if(options.count("paranoid-backup")) {
		// TODO
	}

	
	if(options.count("storage-filename")) {
		storage_filename = options["f"].as<string>();
	} else {
	
		char *home = getenv("HOME");

		if(!home) {
			wxMessageDialog errDialog(NULL, wxString("Error: $HOME not set. Please set $HOME or provide --storage-filname."), wxT("Error"), wxOK|wxCENTRE);
			errDialog.ShowModal();
  	
			return false;
		}

		storage_filename = string(home) + "/.pmate";
	}


 	try {
    	storage=new SyncableStorage(storage_filename);
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
