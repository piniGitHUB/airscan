#include <stdlib.h>

#include "common.h"
#include "sniffer.h"

//!!!TODO LOG_ERR


void *xmalloc(size_t size){
	void *ptr;
	ptr=(void *)(malloc(size));
	if (ptr==NULL){
		//log_err(LEVEL0,(char *)"Failed to alocate memory.Out of memory?");
		//EXIT????
		return NULL;
	}else
		return ptr;
}
