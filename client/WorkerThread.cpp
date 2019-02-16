#include "WorkerThread.hpp"
#include "MainWindow.hpp"
#include <string>
#include <time.h>


using std;

// declare a new type of event, to be used by our WorkerThread class:



wxDEFINE_EVENT(wxEVT_WorkerThreadCompleted, wxThreadEvent);
wxDEFINE_EVENT(wxEVT_WorkerThreadProgress, wxThreadEvent);

wxThread::ExitCode WorkerThread::Entry()
{
    int i;
    /*
    while (!TestDestroy() )
    {
        // ... do a bit of work...
        wxQueueEvent(m_pHandler, new wxThreadEvent(wxEVT_COMMAND_WorkerThread_UPDATE));
    }
    */


    // signal the event handler that this thread is going to be destroyed
    // NOTE: here we assume that using the m_pHandler pointer is safe,
    //       (in this case this is assured by the MyFrame destructor)

    wxThreadEvent *evt;

    printf("Hello from the worker thread!\n");
    sleep(1);

    SendProgressUpdate()

    sleep(1);

    printf("Thread is done!\n");

    wxQueueEvent(m_pHandler, new wxThreadEvent(wxEVT_WorkerThreadCompleted));
    return (wxThread::ExitCode)0;     // success
}

WorkerThread::SendProgressUpdate(string message, int progress) {
    evt = new wxThreadEvent(wxEVT_WorkerThreadProgress);
    ProgressData d = ProgressData(message, progress);
    evt->SetPayload<WorkerThread::ProgressData>(d);
    wxQueueEvent(m_pHandler, evt);
}

WorkerThread::~WorkerThread()
{
    //wxCriticalSectionLocker enter(m_pHandler->m_pThreadCS);
    // the thread is being destroyed; make sure not to leave dangling pointers around
    
    //m_pHandler->m_pThread = NULL;
}
