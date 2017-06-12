#pragma once

#include <list>
#include <string>
#include <vector>

#include <wx/wx.h>



#include <wx/treectrl.h>

class MainWindow : public wxFrame {
    public:
        MainWindow();
    protected:
        void InitMenu();

        wxScrolledWindow *panelRecord;
        wxFlexGridSizer *sizerRecord;
        wxTreeCtrl *recordTree;
        void UpdateRecordPanel();
        void UpdateRecordTree();


        // Intermediate Record Tree Node: This is responsible for turning the flat record structure into a tree structure based on "/" as a delimiter.
        class IRTNode {
       	public:
       		IRTNode(IRTNode *parent, std::string node_name);
       		IRTNode *GetChildForceCreate(std::string new_node_name);
       		void AppendToTreeCtrl(wxTreeCtrl *tree);

       		static std::vector<std::string> SplitPath(std::string path);

			std::string node_name;
       		std::string full_path;
       		bool search_flag;
       		std::list<IRTNode> children;
       		wxTreeItemId item_id;
       		IRTNode *parent;
        };

    private:
        void OnClose(wxCommandEvent& event);

};