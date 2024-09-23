
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

#include "kcpq.h" // cir pkt que h


// this class is a packet oriented circular queue container class.
// its job is to maintain packet oriented circular queues of data
// that can be accessed in a FIFO manner.


// constructor
CircularPacketQueue::CircularPacketQueue ( long size ) : CircularQueue ( size )
{
  m_numpkts = 0;
}


// destructor
CircularPacketQueue::~CircularPacketQueue()
{
}


// append data to tail of buffer
//
// method returns false if no more room available in queue
bool CircularPacketQueue::append ( CircularQueue::DataType* buf, long size )
{
  // lock the queue
  m_packet_queue_lock.lock();

  long pktsize = size + sizeof ( PacketHeader_t );

  // make sure theres enough room left in the queue
  // to accomodate the requested data transfer
  if ( pktsize > ( m_queue_size - m_current_size ) )
  {
    // releae the queue lock
    m_packet_queue_lock.unlock();

    // let 'em know the operation failed
    return false;
  }

  // setup the packet header
  PacketHeader_t pktheader;
  pktheader.m_packet_size = size;

  // append the packet header to the underlying circular queue buffer
  CircularQueue::append ( ( CircularQueue::DataType* ) &pktheader, sizeof ( PacketHeader_t ) );

  // append the users data
  CircularQueue::append ( buf, size );

  // bump packet count
  ++m_numpkts;

  // release the queue lock
  m_packet_queue_lock.unlock();

  // let 'em know the append worked okay
  return true;
}


// retrieve data from head of buffer.
//
// this method returns the number of data bytes retrieved, or zero if
// no more packets are available.  the "size" parameter indicates the
// actual space available in "buf".
long CircularPacketQueue::retrieve ( CircularQueue::DataType* buf, long size )
{
  // lock the queue
  m_packet_queue_lock.lock();

  // make sure there's actual packets available on the queue.
  if ( m_numpkts < 1 )
  {
    // releae the queue lock
    m_packet_queue_lock.unlock();
    return 0;
  }

  // retrieve the packet header
  PacketHeader_t pktheader;
  long hdrsize = CircularQueue::retrieve ( ( CircularQueue::DataType* ) &pktheader, sizeof ( pktheader ) );

  // impossible???
  if ( hdrsize < ( long ) sizeof ( PacketHeader_t ) )
  {
    // releae the queue lock
    m_packet_queue_lock.unlock();
    abort();  // remember "abort" never returns
  }

  // copy the indicated number of bytes of data from the queue to the users buffer
  long datasize = CircularQueue::retrieve ( buf, pktheader.m_packet_size );

  // impossible???
  if ( datasize != pktheader.m_packet_size )
  {
    // releae the queue lock
    m_packet_queue_lock.unlock();
    abort();  // remember "abort" never returns
  }

  // decrement the packet count
  --m_numpkts;

  // releae the queue lock
  m_packet_queue_lock.unlock();

  // let 'em what they got
  return datasize;
}


// this method returns the current number of packets available
// for retrieval from the circular queue.
long CircularPacketQueue::get_packet_count() const
{
  return m_numpkts;
}
