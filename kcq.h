
#ifndef __CIRCULARQUEUE_H__
#define __CIRCULARQUEUE_H__

#include "kpmutex.cc"
// #include "pdsmlib/namespaces.h"

/**
 * \file
 * \brief class \ref CircularQueue
 */


/**
 * \brief This class is the sle circular queue container class.
 * its job is to maintain circular queues of data that
 * can be accessed in a FIFO manner.
 */
class CircularQueue
{
  // *** member variables ***
 public:
  // data type of input buffer
  typedef unsigned char DataType;


 protected:
  // data type of buffer indices
  typedef int IndexType;

  // this is the data buffer which is allocated on the heap
  CircularQueue::DataType* m_queue;
  CircularQueue::IndexType m_queue_size;

  // where to append data
  CircularQueue::IndexType m_tail;

  // where beginning of data starts
  CircularQueue::IndexType m_head;

  // current number of bytes in queue
  long m_current_size;

  // mutex lock to protect access to circular buffer control variables
  PMutex m_lock;

 private:


  // *** methods ***
 public:
  // constructor - "size" indicates number of bytes to allocate for the queue
  CircularQueue ( long size );

  // destructor
  virtual ~CircularQueue();

  // append data to tail of buffer
  //
  // method returns false if no more room available in queue
  virtual bool append ( CircularQueue::DataType* buf, long size );

  // retrieve data from head of buffer.
  //
  // this method returns the number of data bytes retrieved,
  // the same as that requested, or a negative number or
  // zero which indicates the number of bytes that are
  // actually available, which is insufficient to satisfy
  // the request.
  //
  // wait_for_lock allows control of PMUTEX_LOCK from caller
  //
  // NOTE:  once data has been retrieved from the queue it
  // is no longer available (return code > 0).
  virtual long retrieve ( CircularQueue::DataType* buf, long size, bool wait_for_lock = true );

  // this method returns the current number of bytes available
  // for retrieval from the circular queue.
  virtual long get_current_size() const;

  // this method returns that actual size of the circular queue
  // buffer as previously set via the constructor
  virtual long get_queue_size() const;


 protected:
  // disallow default constructor
  CircularQueue() { }

  // disallow copy constructor and assignment operator
  CircularQueue ( CircularQueue& ) { }
  virtual CircularQueue& operator = ( CircularQueue& )
  {
    return *this;
  }


 private:


};

#endif  // __CIRCULARQUEUE_H__

