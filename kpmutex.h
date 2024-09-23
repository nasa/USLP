
#ifndef __PMUTEX_H__
#define __PMUTEX_H__

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <sys/types.h>
#include <unistd.h>
#include <pthread.h>

enum
{
  SUCCESS,
  DEADLOCK,
  PERMISSIONS
};
class PMutex //klmq506 : public SystemBase
{

  // *** member variables ***
 public:
  // size of memory area required to create an
  // interprocess mutex lock (in shared memory)
  enum PMutex_Constants
  {
    NoOwner = -1LL
  };


 protected:
  // posix mutex lock data structure pointer
  volatile pthread_mutex_t* m_mutex;

  // local posix mutex lock data structure
  volatile pthread_mutex_t m_privateMutex;

  // posix mutex lock attribute structure
  volatile pthread_mutexattr_t m_attr;

  // lock owner
  volatile pthread_t m_lockowner;
  volatile pid_t m_lockowner_lwp;

  // as well as user specified information, to help in DEBUGGING
  // mutex lock problems such as deadlock situations, etc
  char m_what[256];

  // flag indicating whether PTHREAD_MUTEX_ERRORCHECK type checks
  // are performed (the default) or whether they are being overridden
  // by the user.
  bool m_override;

  // flag indicating the user has specified an interprocess
  // mutex lock address (in shared memory)
  bool m_useraddress;

  // flag indicating an interprocess mutex lock should be
  // destroyed when this object is destroyed
  bool m_destroyOnExit;


 private:


  // *** methods ***
 public:
  // constructor
  PMutex();

  // destructor
  virtual ~PMutex();

  // obtain lock, method returns true if successful, false if not.
  // NOTE:  "what" is user specifiable information to aide us in
  // mutex lock DEBUGGING.
  virtual bool lock ( bool waitforlock = true, const char* what = NULL,
                      const char* gcc_file_name = NULL, const char* gcc_function_name = NULL, int gcc_lineno = 0 );

  // release lock, method returns true if successful, false if not.
  virtual bool unlock ( const char* what = NULL,
                        const char* gcc_file_name = NULL, const char* gcc_function_name = NULL, int gcc_lineno = 0 );

 protected:
  // disallow copy constructor and assignment operator
  PMutex ( PMutex& ) { }
  virtual PMutex& operator = ( PMutex& )
  {
    return *this;
  }

 private:
  // object initialization method
  void init();

};

#endif  // __PMUTEX_H__

