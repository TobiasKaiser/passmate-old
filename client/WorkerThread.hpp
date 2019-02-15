#include <wx/thread.h>
#include <wx/event.h>

wxDECLARE_EVENT(wxEVT_COMMAND_WorkerThread_COMPLETED, wxThreadEvent);

class MainWindow;

class WorkerThread : public wxThread
{
public: 
    WorkerThread(MainWindow *handler)
        : wxThread(wxTHREAD_DETACHED)
        { m_pHandler = handler; }
    ~WorkerThread();
protected:
    virtual ExitCode Entry();
    MainWindow *m_pHandler;
};