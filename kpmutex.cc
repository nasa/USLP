
// Implementation of the posix threads mutex encapsulation class
//
// This class encapsulates some of the basic posix thread
// mutex functionality.  A mutex should be used when some
// shared resource requires that one and only one thread
// manipulate that resource in any way at any given time,
// i.e. a mutex lock is always an exclusive lock.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>
#include <sys/types.h>
#include <bits/pthreadtypes.h>

#include "kpmutex.h"

static const char* PMUTEX_NEVER_LOCKED = "<never_locked>";

// initialize all data members
void PMutex::init()
{
  m_lockowner = ( pthread_t ) NoOwner;
  m_lockowner_lwp = ( pid_t ) NoOwner;
  m_override = false;
  m_useraddress = false;
  m_destroyOnExit = false;
  memset ( m_what, 0, sizeof ( m_what ) );
  pthread_mutexattr_init ( ( pthread_mutexattr_t* ) &m_attr );
}


// default constructor (actual mutex is private local memory)
PMutex::PMutex()
{
  init();
  m_mutex = &m_privateMutex;
  pthread_mutex_init ( ( pthread_mutex_t* ) m_mutex, ( pthread_mutexattr_t* ) &m_attr );
}

// destructor
PMutex::~PMutex()
{
  if ( ! m_useraddress  ||  ( m_useraddress  &&  m_destroyOnExit ) )
  {
    pthread_mutex_destroy ( ( pthread_mutex_t* ) m_mutex );
  }
}

// obtain lock, method returns true if successful, false if not.
bool PMutex::lock ( bool waitforlock, const char* what, const char* gcc_file_name, const char* gcc_function_name, int gcc_lineno )
{
  int status = 0;
  pthread_t my_threadid = pthread_self();

  // if we are not overriding the ownership checks, and the calling
  // thread does indeed already own this lock, then a dead lock
  // would result, so return that status to the calling thread
  if ( ! m_override  &&  m_lockowner == my_threadid )
  {
    status = DEADLOCK;

  }
  // either we are overriding the ownership checks, or the calling
  // thread does not already own the mutex, so obtain the mutex
  // lock or block trying, unless this is a non-blocking call,
  // then just try to obtain the lock without blocking
  else
  {
    if ( waitforlock )
    {
      status = pthread_mutex_lock ( ( pthread_mutex_t* ) m_mutex );
    }
    else
    {
      status = pthread_mutex_trylock ( ( pthread_mutex_t* ) m_mutex );
    }
  }

  if ( SUCCESS == status )
  {
    m_lockowner = my_threadid;
    // m_lockowner_lwp = gettid();
    m_lockowner_lwp = m_mutex->__data.__owner;


    return true;
  }
  else
  {
    // sanity check, something is SERIOUSLY wrong if we see this message in the standard out
    if ( waitforlock  &&  DEADLOCK != status )
    {
      fprintf ( stderr, "PMutex.lock: ERROR -- obtaining lock, status=%d, what:\"%s\", last what:\"%s\", " \
                "override=%s, m_lockowner=%x, my_threadid=%x, m_mutex=%p, &m_privateMutex=%p -- %s\n",
                status, what, m_what, ( m_override  ?  "true" : "false" ), ( int ) m_lockowner, ( int ) my_threadid,
                m_mutex, &m_privateMutex, strerror ( status ) );
      fflush ( stderr );
    }

    return false;
  }

  // impossible???
  return false;
}


// release lock, method returns true if successful, false if not.
bool PMutex::unlock ( const char* what, const char* gcc_file_name, const char* gcc_function_name, int gcc_lineno )
{
  int status = 0;
  pthread_t my_threadid = pthread_self();

  // if we are checking for lock ownership by the calling thread,
  // and that thread does indeed own the lock, then reset the lock
  // owner and perform the mutex unlock
  if ( m_lockowner == my_threadid )
  {
    m_lockowner = ( pthread_t ) NoOwner;
    m_lockowner_lwp = ( pid_t ) NoOwner;

    status = pthread_mutex_unlock ( ( pthread_mutex_t* ) m_mutex );
  }
  // if we are overriding the lock ownership check, then simply
  // reset the lock owner and perform the unlock no matter what
  else if ( m_override )
  {
    m_lockowner = ( pthread_t ) NoOwner;
    m_lockowner_lwp = ( pid_t ) NoOwner;

    status = pthread_mutex_unlock ( ( pthread_mutex_t* ) m_mutex );

  }
  // otherwise, the current thread does not own the mutex, or the
  // mutex is not locked, and we are not overriding those checks.
  // so tell the calling thread that it does not have permission
  // to perform this unlock.
  else
  {
    if ( 0 != strcmp ( m_what, PMUTEX_NEVER_LOCKED )  &&  ( pthread_t ) NoOwner != m_lockowner )
    {
      fprintf ( stderr,
                "PMutex.unlock: ERROR -- attempt to unlock while not the owner, m_lockowner=%x, m_lockowner_lwp=%d, what:\"%s\", last what:\"%s\"\n",
                ( int ) m_lockowner, ( int ) m_lockowner_lwp, what, m_what );
      fflush ( stderr );
    }

    status = PERMISSIONS;
  }

  if ( SUCCESS == status )
  {
    return true;
  }
  else
  {
    return false;
  }
}
