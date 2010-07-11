#ifndef _X_COMMON_
#define _X_COMMON_

#define LEVEL0 0 
#define LEVEL1 1
#define LEVEL2 2
#define LEVEL3 3
#define LEVEL4 4
#define LEVEL5 5
#define LEVEL6 6
#define LEVEL7 7
#define LEVEL8 8
#define LEVEL9 9
#define LEVEL10 10
#define LEVEL11 11
#define LOGBUFFER_SIZE 128


//not recomended to modify
#define MAX_STR_TO_DISPLAY 255



#define ieee80211mhz2chan(x) \
        (((x) <= 2484) ? \
        (((x) == 2484) ? 14 : ((x) - 2407) / 5) : \
        ((x) / 5) - 1000)




#endif
