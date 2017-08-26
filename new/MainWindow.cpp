#include <sstream>
#include <regex>
#include <string>

#include "MainWindow.hpp"
#include "Application.hpp"
#include "Storage.hpp"

#include <wx/splitter.h>
#include <wx/sizer.h>
#include <wx/clipbrd.h>
#include <wx/textctrl.h>

using namespace std;

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
    wxTextCtrl *entryFilter=new wxTextCtrl( panelLeft, wxID_ANY, wxT(""), wxDefaultPosition, wxDefaultSize, 0);
    entryFilter->Bind(wxEVT_TEXT, &MainWindow::OnFilterUpdated, this);

    recordTree=new wxTreeCtrl(panelLeft, wxID_ANY, wxDefaultPosition, wxDefaultSize, wxTR_DEFAULT_STYLE/*|wxTR_HIDE_ROOT*/);

    wxButton *buttonAdd=new wxButton(panelLeft, wxID_ANY, _T("Add record"));
    wxButton *buttonSync=new wxButton(panelLeft, wxID_ANY, _T("Sync database"));

    wxButton *buttonRemove=new wxButton(panelRight, wxID_ANY, _T("Remove record"));
    wxButton *buttonRename=new wxButton(panelRight, wxID_ANY, _T("Rename record"));
    wxButton *buttonAddField=new wxButton(panelRight, wxID_ANY, _T("Add field"));
    //wxButton *buttonHistory=new wxButton(panelRight, wxID_ANY, _T("History"));

    buttonAdd->Bind(wxEVT_BUTTON, &MainWindow::OnButtonAddRecord, this);
    buttonSync->Bind(wxEVT_BUTTON, &MainWindow::OnButtonSync, this);
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



    //panelRecord->ShowScrollbars(wxSHOW_SB_ALWAYS, wxSHOW_SB_ALWAYS);
}

void MainWindow::OnSize(wxSizeEvent& event) {
    /*//printf("resize event\n");    
    //wxSize size = panelRecord->GetBestVirtualSize();
    //panelRecord->SetVirtualSize( size );
    sizerRecord->FitInside(panelRecord);
    panelRecord->Layout();

    Layout();


    int prX, prY, mX, mY;

    panelRecord->GetSize(&prX, &prY);
    panelRecord->GetVirtualSize(&mX, &mY);



    printf("%04i %04i %04i %04i\n", mX, mY, prX, prY);
    */
    Layout();
}

void MainWindow::OnRecordActivated(wxTreeEvent& event) {
    IRTNode *selected = irt_root.FindByItemId(event.GetItem());


    if(selected && selected->path_connected) {
          Storage &st = wxGetApp().GetStorage();

          cur_record = st.GetRecord(selected->full_path);
          ShowCommitBar(false);

          UpdateRecordPanel();
    }    
}

MainWindow::IRTNode::IRTNode(IRTNode *parent, std::string node_name) {
    this->parent = parent;

    this->node_name=node_name;

    full_path="";
    path_connected = false;

    search_flag = true;
}

MainWindow::IRTNode *MainWindow::IRTNode::GetChildForceCreate(std::string new_node_name) {
    // If we already have it, return that:
    for(IRTNode &node : children) {
        if(node.node_name == new_node_name)
            return &node;
    }

    // Else make a new one, append and return:
    children.push_back(IRTNode(this, new_node_name));

    return &children.back();
}


std::vector<std::string> MainWindow::IRTNode::SplitPath(std::string path) {

    vector<string> ret;
    
    size_t tokEnd = 0;
    while ((tokEnd = path.find("/")) != string::npos) {
        ret.push_back(path.substr(0, tokEnd));
        path.erase(0, tokEnd + 1);
    }
    ret.push_back(path);

    return ret;
}

MainWindow::IRTNode *MainWindow::IRTNode::FindByItemId(const wxTreeItemId &search_id){
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

void MainWindow::IRTNode::AppendToTreeCtrl(wxTreeCtrl *tree) {
    if(parent) {
        item_id = tree->AppendItem(parent->item_id, node_name);
    } else {
        item_id = tree->AddRoot(node_name);
    }

    for(MainWindow::IRTNode &child : children) {
        child.AppendToTreeCtrl(tree);
    }
}

void MainWindow::OnFieldGenerate(wxCommandEvent &evt)
{
    FieldButtonUserData *ud = (FieldButtonUserData *) evt.GetEventUserData();
    cout << "Field generate " << ud->GetFieldName() << ", " << ud->GetValueIdx() << endl;

}

void MainWindow::OnFieldMaskUnmask(wxCommandEvent &evt)
{
    FieldButtonUserData *ud = (FieldButtonUserData *) evt.GetEventUserData();
    cout << "Field mask unmask " << ud->GetFieldName() << ", " << ud->GetValueIdx() << endl;


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
    cout << "Field clip " << ud->GetFieldName() << ", " << ud->GetValueIdx() << endl;

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
    cout << "Field remove " << ud->GetFieldName() << ", " << ud->GetValueIdx() << endl;

    vector<wxTextCtrl *> allValueEntries = cur_record_text_ctrls[ud->GetFieldName()];

    for(const auto &entry : allValueEntries) {
        entry->Enable(false);
        entry->ChangeValue(wxT("")); // in contrast to SetValue, this does not make a event.
    }

    ShowCommitBar(true);

}

void MainWindow::UpdateRecordTree()
{
    Storage &st = wxGetApp().GetStorage();

    recordTree->DeleteAllItems();

    //wxTreeItemId root_id=recordTree->AddRoot("passmate db");

    //IRTNode irt_root(NULL, "passmate db");
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

    irt_root.AppendToTreeCtrl(recordTree);


}

void MainWindow::UpdateRecordPanel() {

    sizerRecord->Clear(true);

    cur_record_text_ctrls.clear();

    std::map<std::string, std::vector<std::string>> fields = cur_record.GetFields();

    wxStaticText *label;


    if(cur_record.IsValid()) {

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

bool MainWindow::isPasswordField(std::string key) {
    regex passwordRegex("^password.*");
    return regex_match(key, passwordRegex);
}

void MainWindow::addFieldToPanel(std::string key, std::vector<std::string> values)
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
            
            entry->SetWindowStyleFlag(entry->GetWindowStyleFlag() | wxTE_PASSWORD);

            buttonGenerate=new wxButton(panelRecord, wxID_ANY, _T("G"));
            buttonGenerate->Bind(wxEVT_BUTTON, &MainWindow::OnFieldGenerate, this, wxID_ANY, wxID_ANY, new FieldButtonUserData(key, i));
            buttonGenerate->SetMinSize(wxSize(30, 30));
            sizerRecord->Add(buttonGenerate, 0, 0, 0);

            buttonHide=new wxButton(panelRecord, wxID_ANY, _T("S"));
            buttonHide->Bind(wxEVT_BUTTON, &MainWindow::OnFieldMaskUnmask, this, wxID_ANY, wxID_ANY, new FieldButtonUserData(key, i));
            buttonHide->SetMinSize(wxSize(30, 30));
            sizerRecord->Add(buttonHide, 0, 0, 0);
        } else {
            sizerRecord->AddSpacer(0);
            sizerRecord->AddSpacer(0);
        }

        buttonCopy=new wxButton(panelRecord, wxID_ANY, _T("C"));
        buttonCopy->Bind(wxEVT_BUTTON, &MainWindow::OnFieldClip, this, wxID_ANY, wxID_ANY, new FieldButtonUserData(key, i));
        buttonCopy->SetMinSize(wxSize(30, 30));
        sizerRecord->Add(buttonCopy, 0, 0, 0);

        if(i==values.size()-1) {
            // remove button comes only once per field
            buttonRemove=new wxButton(panelRecord, wxID_ANY, _T("X"));   
            buttonRemove->Bind(wxEVT_BUTTON, &MainWindow::OnFieldRemove, this, wxID_ANY, wxID_ANY, new FieldButtonUserData(key, i));
            buttonRemove->SetMinSize(wxSize(30, 30));
            sizerRecord->Add(buttonRemove, 0, 0, 0);
        } else {
            sizerRecord->AddSpacer(0);
        }
    }
}

void MainWindow::InitMenu() {
    // Setup menu
    wxMenuBar *menubar = new wxMenuBar();
    wxMenu *menuStore, *menuSync, *menuHelp;
    menuStore = new wxMenu();
    menuSync = new wxMenu();
    menuHelp = new wxMenu();
    menuStore->Append(wxID_EXIT, wxT("&Quit"));


    menuHelp->Append(wxID_ANY, wxT("&Documentation"));;
    menuHelp->Append(wxID_ANY, wxT("Visit &Website"));
    

    menubar->Append(menuStore, wxT("&Store"));
    menubar->Append(menuSync, wxT("S&ync"));
    menubar->Append(menuHelp, wxT("&Help"));

    SetMenuBar(menubar);
}

void MainWindow::OnClose(wxCommandEvent& WXUNUSED(event)) {
    // true is to force the frame to close
    Close(true);
}



void MainWindow::OnButtonAddRecord(wxCommandEvent &evt)
{
    Storage &st = wxGetApp().GetStorage();


    wxTextEntryDialog recordNameDialog(this, wxT("New record name:"));
    if (recordNameDialog.ShowModal() == wxID_OK) {

        cout << "Name:" << recordNameDialog.GetValue() << endl;

        st.NewRecord(string(recordNameDialog.GetValue()));
        st.Save();

        UpdateRecordTree();
    }

}

void MainWindow::OnButtonSync(wxCommandEvent &evt)
{

}

void MainWindow::OnButtonRemove(wxCommandEvent &evt)
{
    if(!cur_record.IsValid()) {
        cout << "x" << endl;
        return;

    }

    Storage &st = wxGetApp().GetStorage();

    wxMessageDialog confirmationDialog(this, wxString("Do you want to remove record "+ cur_record.GetPath()+"?"), wxT("Remove record"), wxYES|wxNO|wxCENTRE);

    if (confirmationDialog.ShowModal() == wxID_YES) {
        string path = cur_record.GetPath();
        st.DeleteRecord(path);
        st.Save();
    }


    cur_record = Record();

    UpdateRecordTree();
    UpdateRecordPanel();


    
}

void MainWindow::ShowCommitBar(bool enable) {
    changesPending=enable;
    if(enable) {
        commitChangeBar->Show();
    } else {
        commitChangeBar->Hide();
    }
    panelRight->Layout();

    //Refresh();
}

void MainWindow::OnButtonRename(wxCommandEvent &evt)
{
    if(!cur_record.IsValid()) {
        cout << "x" << endl;
        return;
    }

    if(changesPending) {
        wxMessageDialog msgBox(this, wxString("Please save record before renaming."), wxT("Rename"), wxOK|wxCENTRE);

        msgBox.ShowModal();

        return;
    }

    Storage &st = wxGetApp().GetStorage();

    wxTextEntryDialog recordNameDialog(this, wxT("New record name:"));
    
    recordNameDialog.SetValue(wxString(cur_record.GetPath()));

    if(recordNameDialog.ShowModal() == wxID_OK) {
        st.MoveRecord(string(recordNameDialog.GetValue()), cur_record.GetPath());
        st.Save();

        cur_record = st.GetRecord(string(recordNameDialog.GetValue()));


        UpdateRecordTree();

        UpdateRecordPanel();

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

                    addFieldToPanel(string(fieldNameDialog.GetValue()), emptyValues);

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

void MainWindow::OnButtonSaveChanges(wxCommandEvent &evt)
{
    Storage &st = wxGetApp().GetStorage();

    std::map<std::string, std::vector<std::string>> guiRecord = GetGUIRecord();

    string proposedChanges = cur_record.SetNewFieldsToStorage(NULL, guiRecord);

    wxMessageDialog confirmationDialog(this, wxString("Do you want to apply the following changes?\n" + proposedChanges), wxT("Save changes"), wxYES|wxNO|wxCENTRE);

    if (confirmationDialog.ShowModal() == wxID_YES) {
        cur_record.SetNewFieldsToStorage(&st, guiRecord);
        st.Save();

        cur_record = st.GetRecord(cur_record.GetPath());
        UpdateRecordPanel();

        ShowCommitBar(false);

    }    
}

void MainWindow::OnButtonHistory(wxCommandEvent &evt)
{

}

void MainWindow::OnRecordFieldTextEvent(wxCommandEvent &evt)
{
    ShowCommitBar(true);
}

void MainWindow::OnFilterUpdated(wxCommandEvent &evt)
{
    cout << "Filter updated!" << endl;

    // Todo
}
