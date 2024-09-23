
#ifndef __CIRCULARPACKETQUEUE_H__
#define __CIRCULARPACKETQUEUE_H__

#include "kcq.cc"

/**
 * \file
 * \brief class \ref CircularPacketQueue
 */


/**
 * \brief This class is a packet oriented circular queue container class.
 * its job is to maintain packet oriented circular queues of data
 * that can be accessed in a FIFO manner.
 */

class CircularPacketQueue : public CircularQueue
{
  // *** member variables ***
 protected:
  // data type of buffer indices
  typedef int IndexType;

  // this structure defines the layout of each packet header.
  typedef struct PacketHeader
  {
    int m_packet_size;
  } PacketHeader_t;

  // current number of bytes in queue
  long m_numpkts;

  // mutex lock to protect access to circular packet buffer control variables
  PMutex m_packet_queue_lock;


  // *** methods ***
 public:
  // constructor - "size" indicates number of bytes to allocate for the queue
  CircularPacketQueue ( long size );

  // destructor
  virtual ~CircularPacketQueue();

  // append to tail of buffer
  //
  // method returns false if no more room available in queue
  virtual bool append ( CircularQueue::DataType* buf, long size );

  // retrieve data from head of buffer.
  //
  // this method returns the number of data bytes retrieved, or zero if
  // no more packets are available.  the "size" parameter indicates the
  // actual space available in "buf".
  virtual long retrieve ( CircularQueue::DataType* buf, long size );

  // this method returns the current number of packets available
  // for retrieval from the circular queue.
  virtual long get_packet_count() const;


 protected:
  // disallow default constructor
  CircularPacketQueue() { }

  // disallow copy constructor and assignment operator
  CircularPacketQueue ( CircularPacketQueue& ) { }
  virtual CircularPacketQueue& operator= ( CircularPacketQueue& )
  {
    return *this;
  }
};

#endif  // __CIRCULARPACKETQUEUE_H__
