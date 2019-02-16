#include "WorkerThread.hpp"
#include "SyncableStorage.hpp"
#include "MainWindow.hpp"
#include <string>
#include <time.h>

using namespace std;

wxDEFINE_EVENT(wxEVT_WorkerThreadCompleted, wxThreadEvent);
wxDEFINE_EVENT(wxEVT_WorkerThreadProgress, wxThreadEvent);

wxThread::ExitCode WorkerThread::Entry()
{
    printf("Hello from the worker thread!\n");
    

    try {
        DoTask();
    } catch(const Storage::Exception &stex) {
        // TODO: Error handling
    }

    printf("Thread is done!\n");

    wxQueueEvent(mainWindow, new wxThreadEvent(wxEVT_WorkerThreadCompleted));
    return (wxThread::ExitCode)0;     // success
}

void WorkerThread::DoTask() {
     sleep(1);
    SendProgressUpdate("Hello World!", 10);
    sleep(1);
    SendProgressUpdate("Hello World!", 20);
    sleep(1);
    SendProgressUpdate("Hello World!", 30);
    sleep(1);
    SendProgressUpdate("Hello World!", 40);
    sleep(1);
    SendProgressUpdate("Hello World!", 50);
    sleep(1);
    SendProgressUpdate("Hello World!", 60);
    sleep(1);
    SendProgressUpdate("Hello World!", 70);
    sleep(1);
    SendProgressUpdate("Hello World!", 80);
    sleep(1);
    SendProgressUpdate("Hello World!", 90);
    sleep(1);
}

void WorkerThread::SendProgressUpdate(string message, int progress) {
    wxThreadEvent *evt;

    evt = new wxThreadEvent(wxEVT_WorkerThreadProgress);
    ProgressData d = ProgressData(message, progress);
    evt->SetPayload<WorkerThread::ProgressData>(d);
    wxQueueEvent(mainWindow, evt);
}

WorkerThread::~WorkerThread()
{

}


void SaveStorageWorkerThread::DoTask()
{
    st->Save();
}
