package il.ac.idc.cs.sinkhole;
import java.util.concurrent.locks.Condition;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;


/**
 * A synchronized bounded-size queue for multithreaded producer-consumer applications.
 * @param <T> Type of data items
 */
public class SynchronizedQueue<T> {

	private T[] buffer;
	private int producers;

	int putptr, takeptr, count, capacity;
	Lock lock;
	Condition notFull;
	Condition notEmpty;
	boolean started = false;
	
	/**
	 * Constructor. Allocates a buffer (an array) with the given capacity and
	 * resets pointers and counters.
	 * @param capacity Buffer capacity
	 */
	@SuppressWarnings("unchecked")
	public SynchronizedQueue(int capacity) {
		this.buffer = (T[]) (new Object[capacity]);
		this.producers = 0;
		this.capacity = capacity;
		this.count = 0;
		this.putptr = this.takeptr = 0;
		lock = new ReentrantLock();
		notEmpty = lock.newCondition();
		notFull = lock.newCondition();
	}
	
	/**
	 * Dequeues the first item from the queue and returns it.
	 * If the queue is empty but producers are still registered to this queue, 
	 * this method blocks until some item is available.
	 * If the queue is empty and no more items are planned to be added to this 
	 * queue (because no producers are registered), this method returns null.
	 * 
	 * @return The first item, or null if there are no more items
	 * @see #registerProducer()
	 * @see #unregisterProducer()
	 */
	public T dequeue() {
		lock.lock();
		
		T x = null;
		try {
			while (count == 0 && producers != 0 || !started)
				notEmpty.await();
			if(count == 0 && producers == 0)
				return null;
			x = buffer[takeptr];
			if (++takeptr == capacity)
				takeptr = 0;
			--count;
			notFull.signal();
		} catch (InterruptedException e) {
			e.printStackTrace();
		} finally {
			lock.unlock();
		}
		return x;
	}

	/**
	 * Enqueues an item to the end of this queue. If the queue is full, this 
	 * method blocks until some space becomes available.
	 * @param item Item to enqueue
	 */
	public void enqueue(T item) {
		lock.lock();
		try {
			while (count == buffer.length)
				notFull.await();
			buffer[putptr] = item;
			if (++putptr == capacity)
				putptr = 0;
			++count;
			notEmpty.signal();
		} catch(InterruptedException e) {
			e.printStackTrace();
		}
		finally {
			lock.unlock();
		}
	}

	/**
	 * Returns the capacity of this queue
	 * @return queue capacity
	 */
	public int getCapacity() {
		return capacity;
	}

	/**
	 * Returns the current size of the queue (number of elements in it)
	 * @return queue size
	 */
	public int getSize() {
		lock.lock();
		int rc = count;
		lock.unlock();
		return rc;
	}
	
	/**
	 * Registers a producer to this queue. This method actually increases the
	 * internal producers counter of this queue by 1. This counter is used to
	 * determine whether the queue is still active and to avoid blocking of
	 * consumer threads that try to dequeue elements from an empty queue, when
	 * no producer is expected to add any more items.
	 * Every producer of this queue must call this method before starting to 
	 * enqueue items, and must also call <see>{@link #unregisterProducer()}</see> when
	 * finishes to enqueue all items.
	 * 
	 * @see #dequeue()
	 * @see #unregisterProducer()
	 */
	public void registerProducer() {
		lock.lock();
		this.producers++;
		started = true;
		lock.unlock();
	}

	/**
	 * Unregisters a producer from this queue. See <see>{@link #registerProducer()}</see>.
	 * @see #dequeue()
	 * @see #registerProducer()
	 */
	public void unregisterProducer() {
		lock.lock();
		this.producers--;
		notEmpty.signalAll();
		lock.unlock();
	}
}
