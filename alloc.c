/**
* Malloc Lab
* CS 241 - Fall 2018
*/

#include <string.h>
#include <unistd.h>


typedef struct meta_data {
	size_t size;
	struct meta_data *next;
	struct meta_data *prev;
	int free;
}meta_data;


static size_t blockSize=(size_t)sizeof(meta_data);
static meta_data *free_head = NULL; //stores the head pointer of doubly linked list of free blocks.

void insert_free_block(meta_data *block_ptr)
{
	block_ptr->free=1;
	if(!free_head) // if there is no free_head pointer make the current block head and return
	{
		free_head=block_ptr;
		free_head->next=free_head;
		free_head->prev=free_head;
		return;
	}
	// if free block is present already insert this free block at the end of list.
	block_ptr->next=free_head;
	block_ptr->prev=free_head->prev;
	free_head->prev->next=block_ptr;
	free_head->prev=block_ptr;
}

meta_data* get_next_block(meta_data* ptr) // returns block pointer of adjacent block
{
	meta_data* x=(meta_data*)((char*)ptr+(ptr->size+blockSize));
	if(x==sbrk(0)) // after this there is no block
	{
		return NULL;
	}
	else
	{
		return x;
	}
}
void remove_free_ptr(meta_data* ptr) //function to remove a free block
{
	ptr->free=0;
	if(ptr==free_head) // if the block going to remove from free list is a freehead.
	{
		if(ptr->next!=free_head)
			free_head=ptr->next;
		else
			free_head=NULL;
	}
	ptr->next->prev=ptr->prev;
	ptr->prev->next=ptr->next;
}
void merge(meta_data* ptr) //merge the adjacent free block together.
{
	meta_data *nextBlockPtr=get_next_block(ptr);
	while(nextBlockPtr && nextBlockPtr->free==1) //recursive merge the block until there are adjacent block available for merging
	{
		ptr->size=ptr->size+blockSize+nextBlockPtr->size;	
		remove_free_ptr(nextBlockPtr); 
		nextBlockPtr=get_next_block(ptr);
	}
	return;
}
void split(meta_data* ptr,size_t size) //split the block 
{
	size_t newSize=ptr->size-size-blockSize;
	ptr->size=size;
	meta_data*x=get_next_block(ptr);
	x->size=newSize;
	insert_free_block(x);
}
meta_data *getFreeBlock(size_t size) //returns a free block that can be utilized
{
	meta_data *presentBlock = free_head;
	meta_data *bestFit=NULL;
	int headCheck=0;
	if(presentBlock) //before searching for a free block merge all the blocks so that blocks of sufficient size can be found
	{
		while(presentBlock)
		{
			if(presentBlock==free_head)
				headCheck++;
			if(headCheck>1)
				break;
			merge(presentBlock);
			presentBlock = presentBlock->next;
		}
	}	
	headCheck=0; //search for best fit block
	if(presentBlock)
	{
		while (presentBlock)
		{
			if(presentBlock==free_head)
				headCheck++;
			if(headCheck>1)
				break;
			if( presentBlock->size >= size)
			{
				if(bestFit)
				{
					if(presentBlock<bestFit && presentBlock->size<2*bestFit->size) //try to get the the block on the bottom end so that the heap has less fragmentation issues
					{
						bestFit=presentBlock;
					}
				}
				else
				{
					bestFit=presentBlock;
				}
			}
			presentBlock = presentBlock->next;
		}	
	}
	if(bestFit)
	{
		if(bestFit->size>size+blockSize) //if the free block found exceeds the size required split it.
		{
			split(bestFit,size);
		}
		remove_free_ptr(bestFit);

	}
	return bestFit;
}


/**
 * Allocate memory block
 *
 * Allocates a block of size bytes of memory, returning a pointer to the
 * beginning of the block.  The content of the newly allocated block of
 * memory is not initialized, remaining with indeterminate values.
 *
 * @param size
 *    Size of the memory block, in bytes.
 *
 * @return
 *    On success, a pointer to the memory block allocated by the function.
 *
 *    The type of this pointer is always void*, which can be cast to the
 *    desired type of data pointer in order to be dereferenceable.
 *
 *    If the function failed to allocate the requested block of memory,
 *    a null pointer is returned.
 *
 * @see http://www.cplusplus.com/reference/clibrary/cstdlib/malloc/
 */
void *malloc(size_t size) {
	meta_data *x;
	if (size <= 0) 
	{
		return NULL;
	}
	x = getFreeBlock(size);
	if (!x) // if no memory is found try to get new space
	{
		x = sbrk(size + blockSize);
		x->size = size;
		x->next = NULL;
		x->free = 0;
		if (!x)
			return NULL;
	}
	return(x+1);
}


/**
 * Deallocate space in memory
 *
 * A block of memory previously allocated using a call to malloc(),
 * calloc() or realloc() is deallocated, making it available again for
 * further allocations.
 *
 * Notice that this function leaves the value of ptr unchanged, hence
 * it still points to the same (now invalid) location, and not to the
 * null pointer.
 *
 * @param ptr
 *    Pointer to a memory block previously allocated with malloc(),
 *    calloc() or realloc() to be deallocated.  If a null pointer is
 *    passed as argument, no action occurs.
 */
void free(void *ptr)
{
	if (!ptr) {
		return;
	} // if pointer is Null return;

	meta_data* block_ptr = (meta_data*)ptr - 1;
	if(free_head==NULL) // if free head is not defined make this free block as the head
	{
		free_head=block_ptr;
		free_head->next=block_ptr;
		free_head->prev=block_ptr;
	}
	else
	{
		insert_free_block(block_ptr); //insert the free block.
	}
	block_ptr->free = 1;
}


/**
 * Reallocate memory block
 *
 * The size of the memory block pointed to by the ptr parameter is changed
 * to the size bytes, expanding or reducing the amount of memory available
 * in the block.
 *
 * The function may move the memory block to a new location, in which case
 * the new location is returned. The content of the memory block is preserved
 * up to the lesser of the new and old sizes, even if the block is moved. If
 * the new size is larger, the value of the newly allocated portion is
 * indeterminate.
 *
 * In case that ptr is NULL, the function behaves exactly as malloc, assigning
 * a new block of size bytes and returning a pointer to the beginning of it.
 *
 * In case that the size is 0, the memory previously allocated in ptr is
 * deallocated as if a call to free was made, and a NULL pointer is returned.
 *
 * @param ptr
 *    Pointer to a memory block previously allocated with malloc(), calloc()
 *    or realloc() to be reallocated.
 *
 *    If this is NULL, a new block is allocated and a pointer to it is
 *    returned by the function.
 *
 * @param size
 *    New size for the memory block, in bytes.
 *
 *    If it is 0 and ptr points to an existing block of memory, the memory
 *    block pointed by ptr is deallocated and a NULL pointer is returned.
 *
 * @return
 *    A pointer to the reallocated memory block, which may be either the
 *    same as the ptr argument or a new location.
 *
 *    The type of this pointer is void*, which can be cast to the desired
 *    type of data pointer in order to be dereferenceable.
 *
 *    If the function failed to allocate the requested block of memory,
 *    a NULL pointer is returned, and the memory block pointed to by
 *    argument ptr is left unchanged.
 *
 * @see http://www.cplusplus.com/reference/clibrary/cstdlib/realloc/
 */
/**
 * Allocate space for array in memory
 *
 * Allocates a block of memory for an array of num elements, each of them size
 * bytes long, and initializes all its bits to zero. The effective result is
 * the allocation of an zero-initialized memory block of (num * size) bytes.
 *
 * @param num
 *    Number of elements to be allocated.
 * @param size
 *    Size of elements.
 *
 * @return
 *    A pointer to the memory block allocated by the function.
 *
 *    The type of this pointer is always void*, which can be cast to the
 *    desired type of data pointer in order to be dereferenceable.
 *
 *    If the function failed to allocate the requested block of memory, a
 *    NULL pointer is returned.
 *
 * @see http://www.cplusplus.com/reference/clibrary/cstdlib/calloc/
 */
void *calloc(size_t num, size_t size) {
	size_t totalSize = num * size;
	void *ptr = malloc(totalSize); //allocate memory using malloc 
	memset(ptr, 0, totalSize); // initialize this memory with 0
	return ptr;
}

void *realloc(void *ptr, size_t size)
{
	if (!ptr) 
	{
		return malloc(size);
	}
	meta_data* x = (meta_data*)ptr - 1;
	if (x->size >= size)
	{
		if(x->size>size+blockSize) // if the size of block required is less than the size just split the block into two parts.
		{
			split(x,size);
		}
		return ptr;
	}
	void *new_ptr; 
	new_ptr = malloc(size); //if a block of higher size is required then call malloc and allocate new memory.
	if (!new_ptr) 
	{
    	return NULL;
	}
	memcpy(new_ptr, ptr, x->size);
	free(ptr);  
	return new_ptr;
}
