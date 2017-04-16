#include <sstream>
#include "MainWindow.hpp"
#include <wx/textctrl.h>
#include <wx/splitter.h>
#include <wx/sizer.h>
#include <wx/treectrl.h>

MainWindow::MainWindow()
    : wxFrame(NULL, wxID_ANY, wxT("Passmate"), wxDefaultPosition, wxSize(0, 0)) {
    
    // Panels
    wxSplitterWindow *splittermain = new wxSplitterWindow(this,wxID_ANY,wxDefaultPosition,wxDefaultSize,wxSP_3D);
    wxPanel *panelLeft=new wxPanel(splittermain,wxID_ANY,wxDefaultPosition,wxDefaultSize,wxTAB_TRAVERSAL|wxNO_BORDER);
    wxPanel *panelRight=new wxPanel(splittermain,wxID_ANY,wxDefaultPosition,wxDefaultSize,wxTAB_TRAVERSAL|wxNO_BORDER);
    splittermain->SplitVertically(panelLeft, panelRight);
    panelRecord=new wxScrolledWindow(panelRight,wxID_ANY,wxDefaultPosition,wxDefaultSize, 0);


    // Widgets
    wxTextCtrl *entryFilter=new wxTextCtrl( panelLeft, wxID_ANY, wxT(""), wxDefaultPosition, wxDefaultSize, 0);

    wxTreeCtrl *treectrl=new wxTreeCtrl(panelLeft);

    wxButton *buttonAdd=new wxButton(panelLeft, wxID_ANY, _T("Add record"));
    wxButton *buttonSync=new wxButton(panelLeft, wxID_ANY, _T("Sync database"));

    wxButton *buttonRemove=new wxButton(panelRight, wxID_ANY, _T("Remove record"));
    wxButton *buttonRename=new wxButton(panelRight, wxID_ANY, _T("Rename record"));
    wxButton *buttonAddField=new wxButton(panelRight, wxID_ANY, _T("Add field"));
    wxButton *buttonSaveChanges=new wxButton(panelRight, wxID_ANY, _T("Save"));
    wxButton *buttonHistory=new wxButton(panelRight, wxID_ANY, _T("History"));

    // Sizing
    panelLeft->SetMinSize(wxSize(150, 200));
    panelRight->SetMinSize(wxSize(250, 200));
    splittermain->SetMinSize(wxSize(800, 500));
    splittermain->SetMinimumPaneSize(10);
    splittermain->SetSashPosition(250);
    splittermain->SetSashGravity(0.0); // When the main window is resized, resize only right panel.


    // Sizer
    wxBoxSizer *windowSizer = new wxBoxSizer(wxVERTICAL);
    windowSizer->Add(splittermain,1,wxBOTTOM|wxLEFT|wxEXPAND,5);
    SetSizer(windowSizer);
    windowSizer->SetSizeHints(this);

    wxBoxSizer *sizerLeft=new wxBoxSizer(wxVERTICAL);
    sizerLeft->Add(new wxStaticText(panelLeft, wxID_ANY, _T("Filter:")), 0, 0, 0);
    sizerLeft->Add(entryFilter,0,wxEXPAND|wxBOTTOM,5);
    sizerLeft->Add(treectrl,1,wxEXPAND|wxBOTTOM,5);
    sizerLeft->Add(buttonAdd,0, wxEXPAND|wxBOTTOM,5);
    sizerLeft->Add(buttonSync,0, wxEXPAND, 0);
    panelLeft->SetSizer(sizerLeft);

    wxBoxSizer *sizerButtonsRight = new wxBoxSizer(wxHORIZONTAL);
    sizerButtonsRight->Add(buttonRename,1, wxEXPAND|wxRIGHT,5);
    sizerButtonsRight->Add(buttonRemove,1, wxEXPAND|wxRIGHT,5);
    sizerButtonsRight->Add(buttonHistory,1, wxEXPAND|wxRIGHT,5);
    sizerButtonsRight->Add(buttonAddField,1, wxEXPAND|wxRIGHT,5);
    sizerButtonsRight->Add(buttonSaveChanges,1, wxEXPAND,0);

    wxBoxSizer *sizerRight=new wxBoxSizer(wxVERTICAL);
    sizerRight->Add(panelRecord,1,wxALL|wxEXPAND,5);
    sizerRight->Add(sizerButtonsRight,0,wxLEFT|wxRIGHT|wxBOTTOM|wxEXPAND,5);
    panelRight->SetSizer(sizerRight);

   

    sizerRecord=new wxFlexGridSizer(6, 5, 5); // 6 cols, 5 pixel horizontal and vertical padding

    
    // Do the menu thing
    InitMenu();

    UpdateRecordPanel();

    Show();

    //panelRecord->ShowScrollbars(wxSHOW_SB_ALWAYS, wxSHOW_SB_ALWAYS);
}

void MainWindow::UpdateRecordPanel() {
    int i;
    for(i=0;i<30;i++) {
        // Make Widgets
        wxStaticText *label=new wxStaticText(panelRecord, wxID_ANY, _T("Password:"));
        wxTextCtrl *entry=new wxTextCtrl( panelRecord, wxID_ANY, wxT(""), wxDefaultPosition, wxDefaultSize, 0);
        wxButton *buttonGenerate=new wxButton(panelRecord, wxID_ANY, _T("G"));
        wxButton *buttonHide=new wxButton(panelRecord, wxID_ANY, _T("H"));
        wxButton *buttonCopy=new wxButton(panelRecord, wxID_ANY, _T("C"));
        wxButton *buttonRemove=new wxButton(panelRecord, wxID_ANY, _T("X"));
        
        buttonGenerate->SetMinSize(wxSize(30, 30));
        buttonHide->SetMinSize(wxSize(30, 30));
        buttonCopy->SetMinSize(wxSize(30, 30));
        buttonRemove->SetMinSize(wxSize(30, 30));

        entry->SetMinSize(wxSize(300, 30));

        // Add to sizer
        sizerRecord->Add(label, 0, wxEXPAND|wxTOP|wxBOTTOM, 5);   
        sizerRecord->Add(entry,1, wxEXPAND, 0);
        sizerRecord->Add(buttonGenerate, 0, 0, 0);
        sizerRecord->Add(buttonHide, 0, 0, 0);
        sizerRecord->Add(buttonCopy, 0, 0, 0);
        sizerRecord->Add(buttonRemove, 0, 0, 0);
    }
    panelRecord->SetSizer(sizerRecord);
    panelRecord->SetScrollRate(10, 10);
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