
// Implementation of the PThread posix threads encapsulation class

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sched.h>
#include <pthread.h>
#include <limits.h>
#include <time.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <errno.h>

#include "kpthread.h"

// defined function or overridden run method
void* PThread_start ( void* arg )
{
  PThread::PThread_arg* parg = ( PThread::PThread_arg* ) arg;
  PThread* pobj = parg->theThis;

  // invoke required run method of user derived class
  void *status = pobj->run ( parg->theArg );
  return status;
}

PThread::PThread ( void *) 
{
}
PThread::~PThread()
{
}
bool PThread::start(void *klmarg)
{
  m_parg.theThis = this;
  // m_parg.theArg = ( void* ) m_arg;
  m_parg.theArg = klmarg;
  pthread_create ( ( pthread_t* ) &m_thread, NULL, PThread_start, &m_parg );
  return true;
}

void* PThread::run ( void* arg )
{
  fprintf ( stderr, "PThread.run(%ld) : base class method invoked - override intended?\n", ( long ) pthread_self() );
  fflush ( stderr );
  return 0;
}
