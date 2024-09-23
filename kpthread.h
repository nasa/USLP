#include <time.h>
#include <signal.h>
#include <pthread.h>

class PThread 
{
  // *** member variables ***
 public:

 protected:

  // user thread startup argument pointer
  volatile void* m_arg;

  // posix thread data structure pointer
  volatile pthread_t m_thread;

  typedef struct PTHREAD_ARG
  {
    PThread* theThis;
    void* theArg;
  } PThread_arg;

  PThread_arg m_parg;

 public:
  PThread ( void* arg = NULL );

  // destructor
  virtual ~PThread();

  // start thread execution
  virtual bool start(void *klmarg);

  virtual void* run ( void* arg = NULL );

 protected:
  // a friend function which is actually the target of the posix
  // pthread_create call, that will execute the appropriate user
  // defined function or overridden run method
  friend void* PThread_start ( void* arg );
};
