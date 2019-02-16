#include <wx/thread.h>
#include <wx/event.h>
#include <string>


wxDECLARE_EVENT(wxEVT_WorkerThreadCompleted, wxThreadEvent);
wxDECLARE_EVENT(wxEVT_WorkerThreadProgress, wxThreadEvent);


class MainWindow;

class WorkerThread : public wxThread
{
public: 
    WorkerThread(MainWindow *handler)
        : wxThread(wxTHREAD_DETACHED)
        { m_pHandler = handler; }
    ~WorkerThread();

    SendProgressUpdate(std::string message, int progress);

    class ProgressData {
        public:
            ProgressData() {};
            ProgressData(std::string message, double progress) {
                this->message = message;
                this->progress = progress;
            }
            std::string message;
            int progress; // 0 --> 100
    };
protected:
    virtual ExitCode Entry();
    MainWindow *m_pHandler;
};
