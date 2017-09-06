#pragma once

#include <list>
#include <string>
#include <vector>

#include <wx/wx.h>
#include <wx/treectrl.h>

#include "Record.hpp"

class MainWindow : public wxFrame {
    public:

        MainWindow();

    protected:

        // Internally used methods
        // -----------------------

        void UpdateRecordPanel();
        void UpdateRecordTree();
        void InitMenu();
        std::map<std::string, std::vector<std::string>> GetGUIRecord();
        void SwitchToRecord(std::string path);
        void SwitchToNoRecord();
        void ShowCommitBar(bool enable);
        void addFieldToPanel(std::string key, std::vector<std::string> values);
        bool isPasswordField(std::string key);

        // Event handler
        // -------------

        void OnRecordActivated(wxTreeEvent& event);
        void OnButtonAddRecord(wxCommandEvent &evt);
        void OnButtonRemove(wxCommandEvent &evt);
        void OnButtonRename(wxCommandEvent &evt);
        void OnButtonAddField(wxCommandEvent &evt);
        void OnButtonSaveChanges(wxCommandEvent &evt);
        void OnRecordFieldTextEvent(wxCommandEvent &evt);
        void OnClose(wxCommandEvent& event);
        void OnSize(wxSizeEvent& event);
        void OnFilterUpdated(wxCommandEvent &evt);
        void OnFilterApply(wxCommandEvent &evt);
        void OnQuit(wxCommandEvent &evt);
        void OnDoc(wxCommandEvent &evt);
        void OnHelp(wxCommandEvent &evt);
        void OnChangePass(wxCommandEvent &evt);

        void OnFieldGenerate(wxCommandEvent &evt);
        void OnFieldMaskUnmask(wxCommandEvent &evt);
        void OnFieldClip(wxCommandEvent &evt);
        void OnFieldRemove(wxCommandEvent &evt);

        void OnSync(wxCommandEvent &evt);
        void OnSyncSetupNewAccount(wxCommandEvent &evt);
        void OnSyncSetup(wxCommandEvent &evt);
        void OnSyncDeleteFromServer(wxCommandEvent &evt);
        void OnSyncReset(wxCommandEvent &evt);
        void OnSyncShowKey(wxCommandEvent &evt);

        // Helper classes
        // --------------

        class FieldButtonUserData : public wxObject {
            // FieldButtonUserData is basically just a pair<string,int>, but manageable by wx memory management, thus usable as user data for button events.
            public:
                FieldButtonUserData(std::string field_name, int value_idx) {
                    this->field_name = field_name;
                    this->value_idx = value_idx;
                }

                std::string GetFieldName() { return field_name; }
                int GetValueIdx() { return value_idx; }
            private:
                int value_idx;
                std::string field_name;

        };

        class IRTNode {
            // Intermediate Record Tree Node: This is responsible for turning the flat record structure into a tree structure based on "/" as a delimiter.
            public:
                // Constructors:
                IRTNode(IRTNode *parent, std::string node_name);
                IRTNode *GetChildForceCreate(std::string new_node_name);
                
                // Methods:
                MainWindow::IRTNode *FindByItemId(const wxTreeItemId &search_id);
                MainWindow::IRTNode *FindByPath(const std::string &path);
                MainWindow::IRTNode *FindFirstFiltered(std::string search);
                void AppendToTreeCtrl(wxTreeCtrl *tree);
                bool ExpandTreeTo(wxTreeCtrl *recordTree, IRTNode *dest);
                bool ApplyFilter(std::string search);

                static std::vector<std::string> SplitPath(std::string path);

                // Attributes:
                std::string node_name;
                std::string full_path;
                bool filter_flag;
                std::list<IRTNode> children;
                wxTreeItemId item_id;
                IRTNode *parent;
                bool path_connected;
        };

        // GUI objects
        // -----------

        wxScrolledWindow *panelRecord;
        wxFlexGridSizer *sizerRecord;
        wxTreeCtrl *recordTree;
        wxPanel *commitChangeBar;
        wxPanel *panelRight;
        wxTextCtrl *entryFilter;

        int menuIdChangePass, menuIdDoc, menuIdHelp;

        int menuIdSync, menuIdSyncSetup, menuIdSyncSetupNewAccount, menuIdSyncDeleteFromServer, menuIdSyncReset, menuIdSyncShowKey;

        // Other attributes
        // ----------------

        std::string prevSearchString;
        IRTNode irt_root;
        Record cur_record;
        std::map<std::string, std::vector<wxTextCtrl*>> cur_record_text_ctrls;        
        bool changesPending;
};