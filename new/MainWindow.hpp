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
        void InitMenu();

        wxScrolledWindow *panelRecord;
        wxFlexGridSizer *sizerRecord;
        wxTreeCtrl *recordTree;
        wxPanel *commitChangeBar;

        bool changesPending;

        void UpdateRecordPanel();
        void UpdateRecordTree();


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

        // Intermediate Record Tree Node: This is responsible for turning the flat record structure into a tree structure based on "/" as a delimiter.
        class IRTNode {
            public:
                IRTNode(IRTNode *parent, std::string node_name);
                IRTNode *GetChildForceCreate(std::string new_node_name);
                void AppendToTreeCtrl(wxTreeCtrl *tree);
                MainWindow::IRTNode *FindByItemId(const wxTreeItemId &search_id);


                static std::vector<std::string> SplitPath(std::string path);

                std::string node_name;
                std::string full_path;
                bool search_flag;
                std::list<IRTNode> children;
                wxTreeItemId item_id;
                IRTNode *parent;
                bool path_connected;
        };

        IRTNode irt_root;

        Record cur_record;
        std::map<std::string, std::vector<wxTextCtrl*>> cur_record_text_ctrls;

        wxPanel *panelRight;

        std::map<std::string, std::vector<std::string>> GetGUIRecord();

        void ShowCommitBar(bool enable);

        void OnRecordActivated(wxTreeEvent& event);
        void OnButtonAddRecord(wxCommandEvent &evt);
        void OnButtonSync(wxCommandEvent &evt);
        void OnButtonRemove(wxCommandEvent &evt);
        void OnButtonRename(wxCommandEvent &evt);
        void OnButtonAddField(wxCommandEvent &evt);
        void OnButtonSaveChanges(wxCommandEvent &evt);
        void OnButtonHistory(wxCommandEvent &evt);
        void OnRecordFieldTextEvent(wxCommandEvent &evt);
        void OnClose(wxCommandEvent& event);
        void OnSize(wxSizeEvent& event);
        void OnFilterUpdated(wxCommandEvent &evt);

        void OnFieldGenerate(wxCommandEvent &evt);
        void OnFieldMaskUnmask(wxCommandEvent &evt);
        void OnFieldClip(wxCommandEvent &evt);
        void OnFieldRemove(wxCommandEvent &evt);


        void addFieldToPanel(std::string key, std::vector<std::string> values);

        bool isPasswordField(std::string key);
  
    private:
  

};