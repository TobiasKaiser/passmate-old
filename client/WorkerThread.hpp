#include <wx/thread.h>
#include <wx/event.h>
#include <string>


wxDECLARE_EVENT(wxEVT_WorkerThreadCompleted, wxThreadEvent);
wxDECLARE_EVENT(wxEVT_WorkerThreadProgress, wxThreadEvent);


class MainWindow;
class SyncableStorage;

class WorkerThread : public wxThread
{
public:
    WorkerThread(MainWindow *handler)
        : wxThread(wxTHREAD_DETACHED)
    {
        mainWindow = handler;
    }
    ~WorkerThread();

    void SendProgressUpdate(std::string message, int progress);

    class ProgressData {
        public:
            ProgressData() {};
            ProgressData(std::string message, int progress) {
                this->message = message;
                this->progress = progress;
            }
            std::string message;
            int progress; // 0 --> 100
    };
protected:
    virtual ExitCode Entry();
    MainWindow *mainWindow;

    virtual void DoTask();
};

class SaveStorageWorkerThread : public WorkerThread
{
public:
    SaveStorageWorkerThread(MainWindow *handler, SyncableStorage *st) : WorkerThread(handler) {
        this->st = st;
    }
protected:
    void DoTask();
    SyncableStorage *st;
};