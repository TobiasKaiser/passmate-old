#pragma once
#include <wx/wx.h>
#include <wx/notebook.h>

class MainWindow : public wxFrame {
    public:
        MainWindow();
    private:
        void OnClose(wxCommandEvent& event);
        void OnResize(wxSizeEvent& evt);


        wxPanel *panel;
};