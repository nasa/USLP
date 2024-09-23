
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

#include "kcq.h"


// its job is to maintain circular queues of data that
// can be accessed in a FIFO manner.

// constructor
CircularQueue::CircularQueue ( long size )
{
  // sizing information
  m_queue_size = size;

  // where to append data
  m_tail = 0;

  // where beginning of data starts
  m_head = 0;

  // current number of bytes in queue
  m_current_size = 0;

  // allocate buffer
  m_queue = ( CircularQueue::DataType* ) malloc ( m_queue_size * sizeof ( CircularQueue::DataType ) );
}


// destructor
CircularQueue::~CircularQueue()
{
  if ( NULL != m_queue )
  {
    free ( m_queue );
  }
}


// append data to tail of buffer
//
// method returns false if no more room available in queue
bool CircularQueue::append ( CircularQueue::DataType* buf, long size )
{
  // lock the queue
  m_lock.lock();

  // make sure theres enough room left in the queue
  // to accomodate the requested data transfer
  if ( size > ( m_queue_size - m_current_size ) )
  {
    // releae the queue lock
    m_lock.unlock();

    // let 'em know the operation failed
    return false;
  }

  // copy data from the users buffer to the queue
  if ( ( m_queue_size - m_tail ) >= size )
  {
    memcpy ( m_queue + m_tail, buf, size );

    // adjust the tail pointer
    m_tail += size;

    // just in case the requested transfer was exactly the same
    // size as what was available at the end of the buffer...
    if ( m_tail >= m_queue_size )
    {
      m_tail = 0;
    }
  }
  else
  {
    long first_piece = m_queue_size - m_tail;
    long second_piece = size - first_piece;

    memcpy ( m_queue + m_tail, buf, first_piece );
    memcpy ( m_queue, buf + first_piece, second_piece );

    // adjust the tail pointer
    m_tail = second_piece;
  }

  // adjust current queue size
  m_current_size += size;

  // release the queue lock
  m_lock.unlock();

  // let 'em know the append worked okay
  return true;

}


// retrieve data from head of buffer.
//
// this method returns the number of data bytes retrieved,
// the same as that requested, or a negative number or
// zero which indicates the number of bytes that are
// actually available, which is insufficient to satisfy
// the request.
//
// NOTE:  once data has been retrieved from the queue it
// is no longer available (return code > 0).
long CircularQueue::retrieve ( CircularQueue::DataType* buf, long size, bool wait_for_lock )
{
  // lock the queue
  bool have_lock = m_lock.lock(wait_for_lock);

  // make sure there's enough data available on the queue
  // to actually satisfy the users request.
  if ( !have_lock || size > m_current_size )
  {
    long current_size = -m_current_size;

    // releae the queue lock
    m_lock.unlock();

    return current_size;
  }

  // copy data from the queue to the users buffer
  if ( ( m_queue_size - m_head ) >= size )
  {
    memcpy ( buf, m_queue + m_head, size );

    // adjust the head pointer
    m_head += size;

    // just in case the requested piece was exactly the same
    // size as what was available at the end of the buffer...
    if ( m_head >= m_queue_size )
    {
      m_head = 0;
    }
  }
  else
  {
    long first_piece = m_queue_size - m_head;
    long second_piece = size - first_piece;

    memcpy ( buf, m_queue + m_head, first_piece );
    memcpy ( buf + first_piece, m_queue, second_piece );

    // adjust the head pointer
    m_head = second_piece;
  }

  // adjust current queue size
  m_current_size -= size;

  // releae the queue lock
    m_lock.unlock();

  // let 'em know they got what they asked for
  return size;

}


// this method returns the current number of bytes available
// for retrieval from the circular queue.
long CircularQueue::get_current_size() const
{
  return m_current_size;
}

// this method returns that actual size of the circular queue
// buffer as previously set via the constructor
long CircularQueue::get_queue_size() const
{
  return m_queue_size;
}
