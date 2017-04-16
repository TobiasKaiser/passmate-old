#include <sstream>
#include "MainWindow.hpp"
#include <wx/textctrl.h>
#include <wx/splitter.h>
#include <wx/sizer.h>
#include <wx/treectrl.h>

MainWindow::MainWindow()
    : wxFrame(NULL, wxID_ANY, wxT("Passmate"), wxDefaultPosition, wxSize(600, 500)) {
    
    //panel = new wxPanel(this, wxID_ANY);

    //panel->Bind(wxEVT_SIZE, &MainWindow::OnResize, this, wxID_ANY);

    wxBoxSizer *windowSizer = new wxBoxSizer(wxHORIZONTAL);
    wxSplitterWindow *splittermain = new wxSplitterWindow(this,wxID_ANY);
    windowSizer->Add(splittermain,1,wxBOTTOM|wxLEFT|wxEXPAND,5);

    wxPanel *panelLeft=new wxPanel(splittermain,wxID_ANY,wxDefaultPosition,wxDefaultSize,wxTAB_TRAVERSAL|wxNO_BORDER);
    
    panelLeft->SetMinSize(wxSize(100, 100));
    wxBoxSizer *sizerLeft=new wxBoxSizer(wxVERTICAL);
    
    wxTreeCtrl *treectrl=new wxTreeCtrl(panelLeft);
    //sizerLeft->SetMinSize(550,-1);
    
    sizerLeft->Add(treectrl,1,wxALL|wxEXPAND,5);
    panelLeft->SetSizer(sizerLeft);

    wxPanel *panelRight=new wxPanel(splittermain,wxID_ANY,wxDefaultPosition,wxDefaultSize,wxTAB_TRAVERSAL|wxNO_BORDER);
    wxStaticBoxSizer *sizerBoxRight=new wxStaticBoxSizer(wxHORIZONTAL,panelRight,_T("Group 2"));
    //sizerBoxRight->SetMinSize(550,-1);
    wxTextCtrl *txt2=new wxTextCtrl( panelRight, wxID_ANY,
    wxT(""), wxDefaultPosition, wxDefaultSize,
    wxTE_MULTILINE);
    sizerBoxRight->Add(txt2,1,wxALL|wxEXPAND,5);
    panelRight->SetSizer(sizerBoxRight);
    panelRight->SetMinSize(wxSize(100, 100));

    splittermain->SetSashGravity(0.0); // When the main window is resized, resize only right panel.
    splittermain->SplitVertically(panelLeft, panelRight);

    SetSizer(windowSizer);
    windowSizer->SetSizeHints(this);


    Show();
}

void MainWindow::OnClose(wxCommandEvent& WXUNUSED(event)) {
    // true is to force the frame to close
    Close(true);
}

void MainWindow::OnResize(wxSizeEvent& evt) {
    panel->Layout();
    //evt.Skip();
}
