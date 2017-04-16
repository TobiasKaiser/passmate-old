#pragma once
#include <wx/wx.h>

class MainWindow : public wxFrame {
    public:
        MainWindow();
    protected:
        void InitMenu();

        wxScrolledWindow *panelRecord;
        wxFlexGridSizer *sizerRecord;
        void UpdateRecordPanel();

    private:
        void OnClose(wxCommandEvent& event);

};