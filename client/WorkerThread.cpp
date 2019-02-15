#include "WorkerThread.hpp"
#include "MainWindow.hpp"
// declare a new type of event, to be used by our WorkerThread class:

wxDEFINE_EVENT(wxEVT_COMMAND_WorkerThread_COMPLETED, wxThreadEvent);


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
    wxQueueEvent(m_pHandler, new wxThreadEvent(wxEVT_COMMAND_WorkerThread_COMPLETED));
    return (wxThread::ExitCode)0;     // success
}

WorkerThread::~WorkerThread()
{
    //wxCriticalSectionLocker enter(m_pHandler->m_pThreadCS);
    // the thread is being destroyed; make sure not to leave dangling pointers around
    
    //m_pHandler->m_pThread = NULL;
}
