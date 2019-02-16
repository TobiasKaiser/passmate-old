#include <sstream>
#include <regex>
#include <string>

#include "MainWindow.hpp"
#include "Application.hpp"
#include "SyncableStorage.hpp"
#include "WorkerThread.hpp"

#include <wx/splitter.h>
#include <wx/sizer.h>
#include <wx/clipbrd.h>
#include <wx/textctrl.h>
#include <wx/artprov.h>
#include <wx/progdlg.h>

using namespace std;

const static char *defaultHostname = "sync.passmate.net";

MainWindow::MainWindow()
    : wxFrame(NULL, wxID_ANY, wxT("Passmate"), wxDefaultPosition, wxSize(0, 0))
    , irt_root(NULL, "")
    , cur_record()
{
    
    // Panels
    wxSplitterWindow *splittermain = new wxSplitterWindow(this,wxID_ANY,wxDefaultPosition,wxDefaultSize,wxSP_3D);
    wxPanel *panelLeft=new wxPanel(splittermain,wxID_ANY,wxDefaultPosition,wxDefaultSize,wxTAB_TRAVERSAL|wxNO_BORDER);
    panelRight=new wxPanel(splittermain,wxID_ANY,wxDefaultPosition,wxDefaultSize,wxTAB_TRAVERSAL|wxNO_BORDER);
    splittermain->SplitVertically(panelLeft, panelRight);
    panelRecord=new wxScrolledWindow(panelRight,wxID_ANY,wxDefaultPosition,wxDefaultSize, wxVSCROLL|wxBORDER_SUNKEN);


    // Widgets
    entryFilter=new wxTextCtrl( panelLeft, wxID_ANY, wxT(""), wxDefaultPosition, wxDefaultSize, wxTE_PROCESS_ENTER);
    entryFilter->Bind(wxEVT_TEXT, &MainWindow::OnFilterUpdated, this);
    entryFilter->Bind(wxEVT_TEXT_ENTER, &MainWindow::OnFilterApply, this);

    recordTree=new wxTreeCtrl(panelLeft, wxID_ANY, wxDefaultPosition, wxDefaultSize, wxTR_DEFAULT_STYLE/*|wxTR_HIDE_ROOT*/);

    wxButton *buttonAdd=new wxButton(panelLeft, wxID_ANY, _T("Add record"));
    buttonAdd->SetBitmap(wxArtProvider::GetBitmap(wxART_PLUS));
    wxButton *buttonSync=new wxButton(panelLeft, wxID_ANY, _T("Sync database"));
    buttonSync->SetBitmap(wxArtProvider::GetBitmap("gtk-network", wxART_MENU));

    buttonRemove=new wxButton(panelRight, wxID_ANY, _T("Remove record"));
    buttonRemove->SetBitmap(wxArtProvider::GetBitmap(wxART_DELETE));
    buttonRename=new wxButton(panelRight, wxID_ANY, _T("Rename record"));
    buttonRename->SetBitmap(wxArtProvider::GetBitmap("gtk-edit", wxART_MENU));
    buttonAddField=new wxButton(panelRight, wxID_ANY, _T("Add field"));
    buttonAddField->SetBitmap(wxArtProvider::GetBitmap(wxART_PLUS));
    
    //wxButton *buttonHistory=new wxButton(panelRight, wxID_ANY, _T("History"));

    buttonAdd->Bind(wxEVT_BUTTON, &MainWindow::OnButtonAddRecord, this);
    buttonSync->Bind(wxEVT_BUTTON, &MainWindow::OnSync, this);
    buttonRemove->Bind(wxEVT_BUTTON, &MainWindow::OnButtonRemove, this);
    buttonRename->Bind(wxEVT_BUTTON, &MainWindow::OnButtonRename, this);
    buttonAddField->Bind(wxEVT_BUTTON, &MainWindow::OnButtonAddField, this);

    //buttonHistory->Bind(wxEVT_BUTTON, &MainWindow::OnButtonHistory, this);


    // Sizing
    panelLeft->SetMinSize(wxSize(200, 200));
    panelRight->SetMinSize(wxSize(500, 200));
    splittermain->SetMinSize(wxSize(700, 400));
    splittermain->SetMinimumPaneSize(10);
    splittermain->SetSashPosition(250);
    splittermain->SetSashGravity(0.0); // When the main window is resized, resize only right panel.


    // Sizer
    wxBoxSizer *windowSizer = new wxBoxSizer(wxVERTICAL);
    windowSizer->Add(splittermain,1,wxBOTTOM|wxLEFT|wxEXPAND,3);
    SetSizer(windowSizer);
    windowSizer->SetSizeHints(this);

    wxBoxSizer *sizerLeft=new wxBoxSizer(wxVERTICAL);
    sizerLeft->Add(new wxStaticText(panelLeft, wxID_ANY, _T("Filter:")), 0, 0, 0);
    sizerLeft->Add(entryFilter,0,wxEXPAND|wxBOTTOM,5);
    sizerLeft->Add(recordTree,1,wxEXPAND|wxBOTTOM,5);
    sizerLeft->Add(buttonAdd,0, wxEXPAND|wxBOTTOM,5);
    sizerLeft->Add(buttonSync,0, wxEXPAND, 0);
    panelLeft->SetSizer(sizerLeft);



    //sizerLeft->SetSizeHints(panelLeft);

    commitChangeBar = new wxPanel(panelRight);


    commitChangeBar->SetBackgroundColour(wxColour(* wxRED));
    
    wxButton *buttonSaveChanges=new wxButton(commitChangeBar, wxID_ANY, _T("Save"));
    buttonSaveChanges->SetBitmap(wxArtProvider::GetBitmap(wxART_FILE_SAVE));
    
    buttonSaveChanges->Bind(wxEVT_BUTTON, &MainWindow::OnButtonSaveChanges, this);

    wxBoxSizer *commitChangeBarSizer = new wxBoxSizer(wxHORIZONTAL);
    commitChangeBarSizer->Add(new wxStaticText(commitChangeBar, wxID_ANY, _T("This record has been changed.")), 1, wxALIGN_CENTER,0); 
    commitChangeBarSizer->Add(buttonSaveChanges,0, 0,0);
    commitChangeBar->SetSizer(commitChangeBarSizer);


    wxBoxSizer *sizerButtonsRight = new wxBoxSizer(wxHORIZONTAL);
    sizerButtonsRight->Add(buttonRename,1, wxEXPAND|wxRIGHT,5);
    sizerButtonsRight->Add(buttonRemove,1, wxEXPAND|wxRIGHT,5);
    //sizerButtonsRight->Add(buttonHistory,1, wxEXPAND|wxRIGHT,5);
    sizerButtonsRight->Add(buttonAddField,1, wxEXPAND|wxRIGHT,5);
    
    wxBoxSizer *sizerRight=new wxBoxSizer(wxVERTICAL);
    sizerRight->Add(commitChangeBar,0,wxLEFT|wxRIGHT|wxTOP|wxEXPAND,2);
    sizerRight->Add(panelRecord,1,wxALL|wxEXPAND,2);
    sizerRight->Add(sizerButtonsRight,0,wxLEFT|wxRIGHT|wxBOTTOM|wxEXPAND,2);
    panelRight->SetSizer(sizerRight);

    //sizerRight->SetSizeHints(panelRight);


    recordTree->Connect(wxID_ANY, wxEVT_TREE_ITEM_ACTIVATED, wxTreeEventHandler(MainWindow::OnRecordActivated), NULL, this);


    sizerRecord=new wxFlexGridSizer(6, 5, 5); // 6 cols, 5 pixel horizontal and vertical padding
    sizerRecord->AddGrowableCol(1);


    ShowCommitBar(false);
    
    UpdateRecordPanel();

    panelRecord->SetSizer(sizerRecord);
    panelRecord->SetScrollRate(0, 10);

    //sizerRecord->SetVirtualSizeHints(panelRecord);

    
    // Do the menu thing
    InitMenu();

    
    UpdateRecordTree();

    Show();

    Connect( wxEVT_SIZE, wxSizeEventHandler( MainWindow::OnSize ) );



void OnWorkerThreadProgress(wxThreadEvent& event);

    Connect(wxEVT_WorkerThreadProgress, wxThreadEventHandler(MainWindow::OnWorkerThreadProgress));
    Connect(wxEVT_WorkerThreadCompleted, wxThreadEventHandler(MainWindow::OnWorkerThreadCompleted));
    /*
wxBEGIN_EVENT_TABLE(MyFrame, wxFrame)
    EVT_COMMAND(wxID_ANY, , MyFrame::OnThreadCompletion)
wxEND_EVENT_TABLE()
    */

    //panelRecord->ShowScrollbars(wxSHOW_SB_ALWAYS, wxSHOW_SB_ALWAYS);
}

void MainWindow::InitMenu()
{
    // Setup menu
    menubar = new wxMenuBar();
    wxMenu *menuStore, *menuSync, *menuHelp;
    menuStore = new wxMenu();
    menuSync = new wxMenu();
    menuHelp = new wxMenu();
    menuIdChangePass = menuStore->Append(wxID_ANY, wxT("Change &Passphrase"))->GetId();
    menuStore->Append(wxID_EXIT, wxT("&Quit"));


    menuIdDoc = menuHelp->Append(wxID_ANY, wxT("&Documentation"))->GetId();
    menuIdHelp = menuHelp->Append(wxID_ANY, wxT("Visit &Website"))->GetId();

    menuIdSyncSetupNewAccount =     menuSync->Append(wxID_ANY, wxT("Create &new account"))->GetId();
    menuIdSyncSetup =               menuSync->Append(wxID_ANY, wxT("&Connection to existing account"))->GetId();
    menuIdSync =                    menuSync->Append(wxID_ANY, wxT("&Sync now"))->GetId();
    menuIdSyncDeleteFromServer =    menuSync->Append(wxID_ANY, wxT("D&elete account"))->GetId();
    menuIdSyncReset =               menuSync->Append(wxID_ANY, wxT("&Disconnect from account"))->GetId();
    menuIdSyncShowKey =             menuSync->Append(wxID_ANY, wxT("Show sync &key"))->GetId();

    menubar->Append(menuStore, wxT("&Store"));
    menubar->Append(menuSync, wxT("S&ync"));
    menubar->Append(menuHelp, wxT("&Help"));

    Connect(wxID_EXIT, wxEVT_COMMAND_MENU_SELECTED, wxCommandEventHandler(MainWindow::OnQuit));
    Connect(menuIdChangePass, wxEVT_COMMAND_MENU_SELECTED, wxCommandEventHandler(MainWindow::OnChangePass));
    Connect(menuIdDoc, wxEVT_COMMAND_MENU_SELECTED, wxCommandEventHandler(MainWindow::OnDoc));
    Connect(menuIdHelp, wxEVT_COMMAND_MENU_SELECTED, wxCommandEventHandler(MainWindow::OnHelp));

    Connect(menuIdSyncSetupNewAccount,  wxEVT_COMMAND_MENU_SELECTED, wxCommandEventHandler(MainWindow::OnSyncSetupNewAccount));
    Connect(menuIdSyncSetup,            wxEVT_COMMAND_MENU_SELECTED, wxCommandEventHandler(MainWindow::OnSyncSetup));
    Connect(menuIdSync,                 wxEVT_COMMAND_MENU_SELECTED, wxCommandEventHandler(MainWindow::OnSync));
    Connect(menuIdSyncDeleteFromServer, wxEVT_COMMAND_MENU_SELECTED, wxCommandEventHandler(MainWindow::OnSyncDeleteFromServer));
    Connect(menuIdSyncReset,            wxEVT_COMMAND_MENU_SELECTED, wxCommandEventHandler(MainWindow::OnSyncReset));
    Connect(menuIdSyncShowKey,          wxEVT_COMMAND_MENU_SELECTED, wxCommandEventHandler(MainWindow::OnSyncShowKey));
    
    SetMenuBar(menubar);

    UpdateMenuEntries();
}



void MainWindow::UpdateMenuEntries()
{
    SyncableStorage &st = wxGetApp().GetStorage();
    bool associated = st.SyncIsAssociated();
    
    // Some entries can be clicked if we are not associated with an account
    menubar->Enable(menuIdSyncSetup, !associated);
    menubar->Enable(menuIdSyncSetupNewAccount, !associated);

    // Some only if we are associated
    menubar->Enable(menuIdSync, associated);
    menubar->Enable(menuIdSyncDeleteFromServer, associated);
    menubar->Enable(menuIdSyncReset, associated);
    menubar->Enable(menuIdSyncShowKey, associated);

}


void MainWindow::SwitchToRecord(std::string path)
{
    // TODO: Ask for confirmation if there are changes to the current record here.

    SyncableStorage &st = wxGetApp().GetStorage();

    cur_record = st.GetRecord(path);
    ShowCommitBar(false);

    UpdateRecordPanel();
}

void MainWindow::SwitchToNoRecord(void)
{
    cur_record = Record();
    
    ShowCommitBar(false);

    UpdateRecordPanel();   
}


std::string MainWindow::lowercaseStr(std::string input)
{
	/* This should work fine for converting all ASCII upper-case characters to ASCII lower-case characters. It should also not mess up UTF-8, because the stuff embedded in the escaped characters will not contain characters that can be interpreted as ASCII 0-127, or so I have heard. */

	string returnMe(input.length(), '\0');

	int i;
	for(i=0;i<input.length();i++) {
		if(input[i]>='A' && input[i]<='Z') {
			returnMe[i] = input[i] - 'A' + 'a'; 
		} else {
			returnMe[i] = input[i];
		}
	}
	
	return returnMe;
}


void MainWindow::UpdateRecordTree()
{
    bool selected_before;
    string selected_before_path;
    IRTNode *selected_before_node = irt_root.FindByItemId(recordTree->GetSelection());
    if(selected_before_node && selected_before_node != &irt_root) {
        selected_before = true;
        selected_before_path = selected_before_node->full_path;
    } else {
        selected_before = false;
        selected_before_node = NULL;
    }


    SyncableStorage &st = wxGetApp().GetStorage();

    recordTree->DeleteAllItems();

 
    irt_root = IRTNode(NULL, "passmate db");

    for (const string &path : st.List()) {
        vector<string> path_split = IRTNode::SplitPath(path);
        

        IRTNode *cur = &irt_root;

        for(unsigned i=0;i<path_split.size();i++) {
            cur = cur->GetChildForceCreate(path_split[i]);
        }

        cur->full_path = path;
        cur->path_connected = true;
    }

    string searchString = string(entryFilter->GetValue());

    if(searchString.length()>0) {
    	searchString = lowercaseStr(searchString);


        irt_root.ApplyFilter(searchString);    
    }
    
    irt_root.AppendToTreeCtrl(recordTree);

    IRTNode *selected_after = NULL;
    if(selected_before) {
        selected_after = irt_root.FindByPath(selected_before_path);
    }

    IRTNode *select_me = NULL;

    if(selected_before && selected_after && selected_after->item_id) {
        select_me = selected_after;
    } else if(searchString.length() > 0) {
        // on empty search string, select nothing, unless there was a selection before.
        select_me = irt_root.FindFirstFiltered(searchString);
    }

    if(prevSearchString.length() > 0 && searchString.length()==0) {
        select_me = NULL;
    }

    if(select_me && select_me->item_id) {
        recordTree->SelectItem(select_me->item_id);
        irt_root.ExpandTreeTo(recordTree, select_me);
    }


    if(irt_root.item_id) {    
        recordTree->Expand(irt_root.item_id);
    }

    prevSearchString = searchString;
}

void MainWindow::UpdateRecordPanel()
{

    sizerRecord->Clear(true);


    bool validRecord = cur_record.IsValid();

    buttonRemove->Enable(validRecord);
    buttonRename->Enable(validRecord);
    buttonAddField->Enable(validRecord);

    cur_record_text_ctrls.clear();
    std::map<std::string, std::vector<std::string>> fields = cur_record.GetFields();
    wxStaticText *label;

    if(validRecord) {

        // Path
        label=new wxStaticText(panelRecord, wxID_ANY, std::string("Path:"));
        sizerRecord->Add(label, 0, wxALIGN_CENTER_VERTICAL|wxALIGN_RIGHT, 0);   
        label=new wxStaticText(panelRecord, wxID_ANY, cur_record.GetPath());
        sizerRecord->Add(label,0, wxEXPAND|wxTOP|wxBOTTOM, 0);

        sizerRecord->AddSpacer(0);
        sizerRecord->AddSpacer(0);
        sizerRecord->AddSpacer(0);
        sizerRecord->AddSpacer(0);

        const bool showRID = false;

        if(showRID) {
            // RID
            label=new wxStaticText(panelRecord, wxID_ANY, std::string("RID:"));
            sizerRecord->Add(label, 0, wxALIGN_CENTER_VERTICAL|wxALIGN_RIGHT, 0);   
            label=new wxStaticText(panelRecord, wxID_ANY, cur_record.GetId());
            sizerRecord->Add(label,0, wxEXPAND|wxTOP|wxBOTTOM, 0);

            sizerRecord->AddSpacer(0);
            sizerRecord->AddSpacer(0);
            sizerRecord->AddSpacer(0);
            sizerRecord->AddSpacer(0);
        }

        for(auto const &cur : fields) {
            addFieldToPanel(cur.first, cur.second);

        }
    }        

    sizerRecord->ShowItems(true);
    panelRecord->Layout();
    sizerRecord->FitInside(panelRecord);
    Refresh();

}

bool MainWindow::isPasswordField(std::string key)
{
    regex passwordRegex("^password.*");
    return regex_match(key, passwordRegex);
}

void MainWindow::addFieldToPanel(std::string key, std::vector<std::string> values, bool was_just_created)
{
    wxStaticText *label;
    wxTextCtrl *entry;
    wxButton *buttonGenerate, *buttonHide, *buttonCopy, *buttonRemove;

    if(values.size() < 1) {
        // TODO: Handle this case this should not be occuring.
        return;
   }

    cur_record_text_ctrls[key] = vector<wxTextCtrl*>();

    label=new wxStaticText(panelRecord, wxID_ANY, key+std::string(":"));
    sizerRecord->Add(label, 0, wxALIGN_CENTER_VERTICAL|wxALIGN_RIGHT, 0);   

    unsigned i = 0;

    for(i=0;i<values.size();i++) {
        if(i > 0) {
            // do not repeat the label in the next line
            sizerRecord->AddSpacer(0);
        }

        // and the second value :)
        entry=new wxTextCtrl( panelRecord, wxID_ANY, values[i], wxDefaultPosition, wxDefaultSize, 0);
        entry->SetMinSize(wxSize(30, 30));
        entry->Bind(wxEVT_TEXT, &MainWindow::OnRecordFieldTextEvent, this);
        sizerRecord->Add(entry, 1, wxEXPAND, 0);
        cur_record_text_ctrls[key].push_back(entry);
    
    
        if(isPasswordField(key)) {    
            
            if(!was_just_created) {
            	entry->SetWindowStyleFlag(entry->GetWindowStyleFlag() | wxTE_PASSWORD);
        	}

            buttonGenerate=new wxButton(panelRecord, wxID_ANY, _T(""));
            buttonGenerate->SetBitmap(wxArtProvider::GetBitmap("gtk-execute", wxART_MENU));
            buttonGenerate->Bind(wxEVT_BUTTON, &MainWindow::OnFieldGenerate, this, wxID_ANY, wxID_ANY, new FieldButtonUserData(key, i));
            buttonGenerate->SetMinSize(wxSize(30, 30));
            sizerRecord->Add(buttonGenerate, 0, 0, 0);

            buttonHide=new wxButton(panelRecord, wxID_ANY, _T(""));
            buttonHide->SetBitmap(wxArtProvider::GetBitmap("gtk-italic", wxART_MENU));
            buttonHide->Bind(wxEVT_BUTTON, &MainWindow::OnFieldMaskUnmask, this, wxID_ANY, wxID_ANY, new FieldButtonUserData(key, i));
            buttonHide->SetMinSize(wxSize(30, 30));
            sizerRecord->Add(buttonHide, 0, 0, 0);
        } else {
            sizerRecord->AddSpacer(0);
            sizerRecord->AddSpacer(0);
        }

        buttonCopy=new wxButton(panelRecord, wxID_ANY, _T(""));
        buttonCopy->SetBitmap(wxArtProvider::GetBitmap(wxART_COPY));
    
        buttonCopy->Bind(wxEVT_BUTTON, &MainWindow::OnFieldClip, this, wxID_ANY, wxID_ANY, new FieldButtonUserData(key, i));
        buttonCopy->SetMinSize(wxSize(30, 30));
        sizerRecord->Add(buttonCopy, 0, 0, 0);

        if(i==values.size()-1) {
            // remove button comes only once per field
            buttonRemove=new wxButton(panelRecord, wxID_ANY, _T(""));   
            buttonRemove->SetBitmap(wxArtProvider::GetBitmap(wxART_MINUS));
            buttonRemove->Bind(wxEVT_BUTTON, &MainWindow::OnFieldRemove, this, wxID_ANY, wxID_ANY, new FieldButtonUserData(key, i));
            buttonRemove->SetMinSize(wxSize(30, 30));
            sizerRecord->Add(buttonRemove, 0, 0, 0);
        } else {
            sizerRecord->AddSpacer(0);
        }
    }
}

void MainWindow::ShowCommitBar(bool enable)
{
    changesPending=enable;
    if(enable) {
        commitChangeBar->Show();
    } else {
        commitChangeBar->Hide();
    }
    panelRight->Layout();
}

std::map<std::string, std::vector<std::string>>  MainWindow::GetGUIRecord()
{
    std::map<std::string, std::vector<std::string>> ret;
    for(auto const &curField : cur_record_text_ctrls) {
        if(!curField.second[0]->IsThisEnabled()) {
            continue; // the field has been removed and is now grayed out until we press save.
        }
        ret[curField.first] = vector<string>();
        for(auto const &curValue : curField.second) {
             ret[curField.first].push_back(string(curValue->GetValue()));
        }
    }

    return ret;
}

bool MainWindow::confirmPass() {
    SyncableStorage &st = wxGetApp().GetStorage();

    wxPasswordEntryDialog passwordDialog(NULL, wxT("Please re-enter passphrase:"));
    
    do {
        passwordDialog.SetValue(wxT(""));

        if(passwordDialog.ShowModal() != wxID_OK) {
            return false;
        }

        if( st.CheckPassphrase(string(passwordDialog.GetValue())) ) {
            return true;
        } else {
            wxMessageDialog errDialog(NULL, wxString("Error: Wrong passphrase"), wxT("Error"), wxOK|wxCENTRE);
            errDialog.ShowModal();          

        }
    } while(1);
}


// Event handler methods
// ---------------------

void MainWindow::OnWorkerThreadProgress(wxThreadEvent& event) {
    printf("Oh look at that! We got a thread progress event!\n");
    WorkerThread::ProgressData progress = event.GetPayload<WorkerThread::ProgressData>();

    progressDialog->Update(progress.progress, progress.message);
}

void MainWindow::OnWorkerThreadCompleted(wxThreadEvent& event) {
    printf("Oh look at that! We got a thread completed event!\n");
    delete progressDialog;
}

void MainWindow::OnChangePass(wxCommandEvent &evt) {
    SyncableStorage &st = wxGetApp().GetStorage();

    // Check previous passphrase
    if(!confirmPass()) {
        return;
    }


    // Set new passphrase
    wxPasswordEntryDialog passwordDialog1(NULL, wxT("Enter new passphrase:"));
    wxPasswordEntryDialog passwordDialog2(NULL, wxT("Repeat new passphrase:"));
    
    bool passwordsMatching;
    do {
        passwordDialog1.SetValue(wxString(""));
        passwordDialog2.SetValue(wxString(""));
        if(passwordDialog1.ShowModal() != wxID_OK) {
            return;
        }
        if(passwordDialog2.ShowModal() != wxID_OK) {
            return;
        }
        passwordsMatching=(string(passwordDialog1.GetValue()) == string(passwordDialog2.GetValue()));
        if(!passwordsMatching) {
            wxMessageDialog errDialog(NULL, wxString("You entered two different passphrases. Please try again."), wxT("Error"), wxOK|wxCENTRE);
            errDialog.ShowModal();
        }

    } while (!passwordsMatching);

    try {
        cout << string(passwordDialog1.GetValue()) << endl;
        st.SetPassphrase(string(passwordDialog1.GetValue()));
        st.Save();
    } catch(const Storage::Exception &stex) {
        wxMessageDialog errDialog(NULL, wxString("Error: "+ string(stex.what())), wxT("Error"), wxOK|wxCENTRE);
        errDialog.ShowModal();
    }
}

void MainWindow::OnDoc(wxCommandEvent &evt) {
    wxLaunchDefaultBrowser("https://www.passmate.net/docs/", 0);
}

void MainWindow::OnHelp(wxCommandEvent &evt) {
    wxLaunchDefaultBrowser("https://www.passmate.net/", 0);
}


void MainWindow::OnQuit(wxCommandEvent &evt) {
    // menu

    Close(true);
}

void MainWindow::OnClose(wxCommandEvent& WXUNUSED(event))
{
    // true is to force the frame to close
    Close(true);
}

void MainWindow::OnButtonAddRecord(wxCommandEvent &evt)
{
    SyncableStorage &st = wxGetApp().GetStorage();


    wxTextEntryDialog recordNameDialog(this, wxT("New record name:"));
    if (recordNameDialog.ShowModal() == wxID_OK) {
        string path(recordNameDialog.GetValue());

        try {
            progressDialog = new wxProgressDialog("In progess", "Please wait...");

            WorkerThread *t = new WorkerThread(this);
            if ( t->Run() != wxTHREAD_NO_ERROR )
            {
                wxLogError("Can't create the thread!");
                delete t;
                t = NULL;
            }
            printf("Thread created!\n");


            /*
			// This needs to be done before creating a new value
			// to prevent the software from crashing when it tries to select an entry from the record tree which is not shown due to filtering.
    		entryFilter->SetValue("");

            st.NewRecord(path);
            st.Save();
            SwitchToRecord(path);
            UpdateRecordTree();
            recordTree->SelectItem(irt_root.FindByPath(path)->item_id);
            */

        } catch(const Storage::Exception &stex) {
            wxMessageDialog errDialog(NULL, wxString("Error: "+ string(stex.what())), wxT("Error"), wxOK|wxCENTRE);
            errDialog.ShowModal();
        }
    }
}

void MainWindow::OnButtonRemove(wxCommandEvent &evt)
{
    if(!cur_record.IsValid()) {
        return;
    }

    SyncableStorage &st = wxGetApp().GetStorage();

    wxMessageDialog confirmationDialog(this, wxString("Do you want to remove record "+ cur_record.GetPath()+"?"), wxT("Remove record"), wxYES|wxNO|wxCENTRE);

    if (confirmationDialog.ShowModal() == wxID_YES) {
        string path = cur_record.GetPath();
        try {
            st.DeleteRecord(path);
            st.Save();
            UpdateRecordTree();
            SwitchToNoRecord();
        } catch(const Storage::Exception &stex) {
            wxMessageDialog errDialog(NULL, wxString("Error: "+ string(stex.what())), wxT("Error"), wxOK|wxCENTRE);
            errDialog.ShowModal();
        }
    }

}

void MainWindow::OnButtonRename(wxCommandEvent &evt)
{
    if(!cur_record.IsValid()) {
        return;
    }

    if(changesPending) {
        wxMessageDialog msgBox(this, wxString("Please save record before renaming."), wxT("Rename"), wxOK|wxCENTRE);
        msgBox.ShowModal();

        return;
    }

    SyncableStorage &st = wxGetApp().GetStorage();

    wxTextEntryDialog recordNameDialog(this, wxT("New record name:"));
    
    recordNameDialog.SetValue(wxString(cur_record.GetPath()));

    if(recordNameDialog.ShowModal() == wxID_OK) {
        try {
            st.MoveRecord(string(recordNameDialog.GetValue()), cur_record.GetPath());
            st.Save();
            cur_record = st.GetRecord(string(recordNameDialog.GetValue()));
            UpdateRecordTree();
            UpdateRecordPanel();
        } catch(const Storage::Exception &stex) {
            wxMessageDialog errDialog(NULL, wxString("Error: "+ string(stex.what())), wxT("Error"), wxOK|wxCENTRE);
            errDialog.ShowModal();
        }
    }
    
}

void MainWindow::OnButtonAddField(wxCommandEvent &evt)
{
    if(!cur_record.IsValid()) {
        return;
    }

    wxTextEntryDialog fieldNameDialog(this, wxT("New field name:"));
    wxTextEntryDialog valueCountDialog(this, wxT("Number of values:"));
    valueCountDialog.SetValue("1");
    if (fieldNameDialog.ShowModal() == wxID_OK) {
        while(true) {
            if(valueCountDialog.ShowModal() == wxID_OK) {
                int count = atoi(valueCountDialog.GetValue());

                if(count>0) {  
                    std::vector<std::string> emptyValues;

                    for(int i=0;i<count;i++) {
                        emptyValues.push_back(std::string(""));
                    }

                    addFieldToPanel(string(fieldNameDialog.GetValue()), emptyValues, true);

                    sizerRecord->ShowItems(true);
                    panelRecord->Layout();
                    sizerRecord->FitInside(panelRecord);
                    
                    ShowCommitBar(true);

                    Refresh();  

                    break;
                }
            } else {
                break;
            }
        }   
    }
    
}

void MainWindow::OnButtonSaveChanges(wxCommandEvent &evt)
{
    SyncableStorage &st = wxGetApp().GetStorage();

    std::map<std::string, std::vector<std::string>> guiRecord = GetGUIRecord();

    string proposedChanges = cur_record.SetNewFieldsToStorage(NULL, guiRecord);

    wxMessageDialog confirmationDialog(this, wxString("Do you want to apply the following changes?\n" + proposedChanges), wxT("Save changes"), wxYES|wxNO|wxCENTRE);

    if (confirmationDialog.ShowModal() == wxID_YES) {
        try {
            cur_record.SetNewFieldsToStorage(&st, guiRecord);
            st.Save();
        } catch(const Storage::Exception &stex) {
            wxMessageDialog errDialog(NULL, wxString("Error: "+ string(stex.what())), wxT("Error"), wxOK|wxCENTRE);
            errDialog.ShowModal();
        }
        cur_record = st.GetRecord(cur_record.GetPath());
        UpdateRecordPanel();

        ShowCommitBar(false);

    }    
}

void MainWindow::OnRecordFieldTextEvent(wxCommandEvent &evt)
{
    ShowCommitBar(true);
}

void MainWindow::OnFilterApply(wxCommandEvent &evt)
{
    IRTNode *selected = irt_root.FindByItemId(recordTree->GetSelection());

    if(selected && selected->path_connected) {
        SwitchToRecord(selected->full_path);
    }
}

void MainWindow::OnFilterUpdated(wxCommandEvent &evt)
{
    UpdateRecordTree();
}


void MainWindow::OnRecordActivated(wxTreeEvent& event)
{
    IRTNode *selected = irt_root.FindByItemId(event.GetItem());

    if(selected && selected->path_connected) {
        SwitchToRecord(selected->full_path);
    }    
}


void MainWindow::OnFieldGenerate(wxCommandEvent &evt)
{
    FieldButtonUserData *ud = (FieldButtonUserData *) evt.GetEventUserData();
    cout << "Field generate " << ud->GetFieldName() << ", " << ud->GetValueIdx() << endl;

    // TODO
}

void MainWindow::OnFieldMaskUnmask(wxCommandEvent &evt)
{
    FieldButtonUserData *ud = (FieldButtonUserData *) evt.GetEventUserData();

    wxTextCtrl *entry = cur_record_text_ctrls[ud->GetFieldName()][ud->GetValueIdx()];


    long flags = entry->GetWindowStyleFlag();
    if ((flags & wxTE_PASSWORD)) {
        // password is masked, so unmask it now
        entry->SetWindowStyleFlag(flags & ~wxTE_PASSWORD);
    } else {
        // password is unmasked, so mask it now
        entry->SetWindowStyleFlag(flags | wxTE_PASSWORD);
    }

    entry->Refresh();
    
}

void MainWindow::OnFieldClip(wxCommandEvent &evt)
{
    FieldButtonUserData *ud = (FieldButtonUserData *) evt.GetEventUserData();
    
    wxTextCtrl *entry = cur_record_text_ctrls[ud->GetFieldName()][ud->GetValueIdx()];

    //wxClipboard clipboard = wxClipboard();
    if(wxTheClipboard->Open()) {
        //clipboard.Clear();
        wxTheClipboard->SetData( new wxTextDataObject( entry->GetValue() ) );
        wxTheClipboard->Flush();
        wxTheClipboard->Close();      
    }
}

void MainWindow::OnFieldRemove(wxCommandEvent &evt)
{
    FieldButtonUserData *ud = (FieldButtonUserData *) evt.GetEventUserData();
    
    vector<wxTextCtrl *> allValueEntries = cur_record_text_ctrls[ud->GetFieldName()];

    for(const auto &entry : allValueEntries) {
        entry->Enable(false);
        entry->ChangeValue(wxT("")); // in contrast to SetValue, this does not make a event.
    }

    ShowCommitBar(true);
}

void MainWindow::OnSize(wxSizeEvent& event)
{
    Layout();
}



// This is both the always-on button and the selectively enabled menu entry
void MainWindow::OnSync(wxCommandEvent &evt)
{
    SyncableStorage &st = wxGetApp().GetStorage();
    if(!st.SyncIsAssociated()) {
        // ideally we should show an explaination and an option dialog to setup, connect or cancel
        // but in the meantime let's just show an error message
        wxMessageDialog errDialog(NULL, wxString("Error: Not associated with any sync account. Please setup sync first."), wxT("Error"), wxOK|wxCENTRE);
        errDialog.ShowModal();
        return;
    }

    try {
        string summary = st.Sync();
        wxMessageDialog errDialog(NULL, wxString("Sync summary:\n"+ summary), wxT("Summary"), wxOK|wxCENTRE);
        errDialog.ShowModal();

        st.Save();
    } catch(const Storage::Exception &stex) {
        wxMessageDialog errDialog(NULL, wxString("Error: "+ string(stex.what())), wxT("Error"), wxOK|wxCENTRE);
        errDialog.ShowModal();
    }

    UpdateMenuEntries();
 
	UpdateRecordTree();
	UpdateRecordPanel();   
}

void MainWindow::OnSyncSetupNewAccount(wxCommandEvent &evt)
{
    SyncableStorage &st = wxGetApp().GetStorage();
    
    if(st.SyncIsAssociated()) {
        // Should never happen, because of menu item enabled state
        return;
    }

    wxTextEntryDialog hostnameDialog(this, wxT("Remote hostname:"));
    hostnameDialog.SetValue(wxString(defaultHostname));
    if (hostnameDialog.ShowModal() != wxID_OK) {
        return;
    }
    string hostname(hostnameDialog.GetValue());

    try {
        string summary = st.SyncSetupNewAccount(hostname);
        wxMessageDialog errDialog(NULL, wxString("Sync setup new account summary:\n"+ summary), wxT("Summary"), wxOK|wxCENTRE);
        errDialog.ShowModal();

        st.Save();
    } catch(const Storage::Exception &stex) {
        wxMessageDialog errDialog(NULL, wxString("Error: "+ string(stex.what())), wxT("Error"), wxOK|wxCENTRE);
        errDialog.ShowModal();
    }

    UpdateMenuEntries();
}

void MainWindow::OnSyncSetup(wxCommandEvent &evt)
{
    SyncableStorage &st = wxGetApp().GetStorage();
    
    if(st.SyncIsAssociated()) {
        // Should never happen, because of menu item enabled state
        return;
    }

    wxTextEntryDialog hostnameDialog(this, wxT("Remote hostname:"));
    hostnameDialog.SetValue(wxString(defaultHostname));
    if (hostnameDialog.ShowModal() != wxID_OK) {
        return;
    }


    wxTextEntryDialog syncKeyDialog(this, wxT("Sync key:"));
    if (syncKeyDialog.ShowModal() != wxID_OK) {
        return;
    }
  
    string hostname(hostnameDialog.GetValue());
    string syncKey(syncKeyDialog.GetValue());

    try {
        string summary = st.SyncSetup(hostname, syncKey);
        wxMessageDialog errDialog(NULL, wxString("Sync setup summary:\n"+ summary), wxT("Summary"), wxOK|wxCENTRE);
        errDialog.ShowModal();

        st.Save();

    } catch(const Storage::Exception &stex) {
        wxMessageDialog errDialog(NULL, wxString("Error: "+ string(stex.what())), wxT("Error"), wxOK|wxCENTRE);
        errDialog.ShowModal();
    }

    UpdateMenuEntries();

    UpdateRecordTree();
	UpdateRecordPanel();
}

void MainWindow::OnSyncDeleteFromServer(wxCommandEvent &evt)
{
    SyncableStorage &st = wxGetApp().GetStorage();
    
    if(!st.SyncIsAssociated()) {
        // Should never happen, because of menu item enabled state
        return;
    }
    
    wxMessageDialog confirmationDialog(this, wxString("Do you want to delete all sync data from server?"), wxT("Sync delete from server"), wxYES|wxNO|wxCENTRE);
    if (confirmationDialog.ShowModal() != wxID_YES) {
        return;
    }
 
    try {
        string summary = st.SyncReset(true);
        wxMessageDialog errDialog(NULL, wxString("Sync delete from server summary:\n"+ summary), wxT("Summary"), wxOK|wxCENTRE);
        errDialog.ShowModal();

        st.Save();

    } catch(const Storage::Exception &stex) {
        wxMessageDialog errDialog(NULL, wxString("Error: "+ string(stex.what())), wxT("Error"), wxOK|wxCENTRE);
        errDialog.ShowModal();
    }

    UpdateMenuEntries();
}

void MainWindow::OnSyncReset(wxCommandEvent &evt)
{
    SyncableStorage &st = wxGetApp().GetStorage();
    
    if(!st.SyncIsAssociated()) {
        // Should never happen, because of menu item enabled state
        return;
    }

    wxMessageDialog confirmationDialog(this, wxString("Do you want to reset your local sync connection and keep sync data on server?"), wxT("Sync reset"), wxYES|wxNO|wxCENTRE);
    if (confirmationDialog.ShowModal() != wxID_YES) {
        return;
    }

    try {
        string summary = st.SyncReset(false);
        wxMessageDialog errDialog(NULL, wxString("Sync reset summary:\n"+ summary), wxT("Summary"), wxOK|wxCENTRE);
        errDialog.ShowModal();

        st.Save();
    } catch(const Storage::Exception &stex) {
        wxMessageDialog errDialog(NULL, wxString("Error: "+ string(stex.what())), wxT("Error"), wxOK|wxCENTRE);
        errDialog.ShowModal();
    }


    UpdateMenuEntries();
}

void MainWindow::OnSyncShowKey(wxCommandEvent &evt)
{
    SyncableStorage &st = wxGetApp().GetStorage();
    
    if(!st.SyncIsAssociated()) {
        // Should never happen, because of menu item enabled state
        return;
    }

    // Check passphrase for security
    if(!confirmPass()) {
        return;
    }
    try {
        string key = st.SyncGetKey();
        wxMessageDialog errDialog(NULL, wxString("Sync key:\n"+ key), wxT("Sync key"), wxOK|wxCENTRE);
        errDialog.ShowModal();

    } catch(const Storage::Exception &stex) {
        wxMessageDialog errDialog(NULL, wxString("Error: "+ string(stex.what())), wxT("Error"), wxOK|wxCENTRE);
        errDialog.ShowModal();
    }
}


// IRTNode methods
// ---------------

MainWindow::IRTNode::IRTNode(IRTNode *parent, std::string node_name)
{
    this->parent = parent;

    this->node_name=node_name;

    full_path="";
    path_connected = false;

    filter_flag = true;
}

MainWindow::IRTNode *MainWindow::IRTNode::GetChildForceCreate(std::string new_node_name)
{
    // If we already have it, return that:
    for(IRTNode &node : children) {
        if(node.node_name == new_node_name)
            return &node;
    }

    // Else make a new one, append and return:
    children.push_back(IRTNode(this, new_node_name));

    return &children.back();
}


std::vector<std::string> MainWindow::IRTNode::SplitPath(std::string path)
{
    vector<string> ret;
    
    size_t tokEnd = 0;
    while ((tokEnd = path.find("/")) != string::npos) {
        ret.push_back(path.substr(0, tokEnd));
        path.erase(0, tokEnd + 1);
    }
    ret.push_back(path);

    return ret;
}

MainWindow::IRTNode *MainWindow::IRTNode::FindByPath(const std::string &path)
{
    if(full_path == path)
        return this;

    for(IRTNode &child : children) {
        IRTNode *result;
        result = child.FindByPath(path);

        if(result)
            return result;
    }

    return NULL;
}


MainWindow::IRTNode *MainWindow::IRTNode::FindByItemId(const wxTreeItemId &search_id)
{
    if(item_id == search_id)
        return this;

    for(IRTNode &child : children) {
        IRTNode *result;
        result = child.FindByItemId(search_id);

        if(result)
            return result;
    }

    return NULL;
}


void MainWindow::IRTNode::AppendToTreeCtrl(wxTreeCtrl *tree)
{
    if(!filter_flag)
        return;

    if(parent) {
        item_id = tree->AppendItem(parent->item_id, node_name);
    } else {
        item_id = tree->AddRoot(node_name);
    }

    for(MainWindow::IRTNode &child : children) {
        child.AppendToTreeCtrl(tree);
    }
}

bool MainWindow::IRTNode::ApplyFilter(std::string search)
{
    filter_flag = false;


    for(IRTNode &child : children) {
        if(child.ApplyFilter(search))
            filter_flag = true;
    }

    string lowercase_full_path = lowercaseStr(full_path);

    if(!filter_flag && (lowercase_full_path.find(search) != string::npos)) {
        filter_flag = true;
    }

    return filter_flag;
}

MainWindow::IRTNode *MainWindow::IRTNode::FindFirstFiltered(std::string search)
{
    if(filter_flag && path_connected) {
        return this;
    }

    for(IRTNode &child : children) {
        IRTNode *ret;
        ret = child.FindFirstFiltered(search);
        if(ret) {
            return ret;
        }
    }
    return NULL;
}

bool MainWindow::IRTNode::ExpandTreeTo(wxTreeCtrl *recordTree, IRTNode *dest)
{
    if(dest == this) {
        if(item_id)
            recordTree->Expand(item_id);
        return true;
    }

    for(IRTNode &child : children) {
        if(child.ExpandTreeTo(recordTree, dest)) {
            if(item_id)
                recordTree->Expand(item_id);
            return true;
        }
    }

    return false;
}
