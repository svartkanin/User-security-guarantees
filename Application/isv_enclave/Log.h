#ifndef ENC_LOG_H
#define ENC_LOG_H
#ifdef	__cplusplus
extern "C" {
#endif

#pragma warning (disable: 4273)
extern int printf(const char *fmt, ...);
#pragma warning (default: 4273) 

enum {
	LOG_LVL_NONE, // 0
	LOG_LVL_CRITICAL, // 1
	LOG_LVL_WARNING, // 2
	LOG_LVL_NOTICE, // 3
	LOG_LVL_LOG, // 4
	LOG_LVL_DEBUG, // 5
	LOG_LVL_NEVER // 6
};


 
//#ifndef LOG_BUILD_LEVEL
//#ifdef NDEBUG
//#define LOG_BUILD_LEVEL LOG_LVL_CRITICAL
//#else
#define LOG_BUILD_LEVEL LOG_LVL_DEBUG
//#endif
//#endif
 
extern unsigned char log_run_level;
 
extern const char * log_level_strings [];
 
// The BUILD_LOG_LEVEL defines what will be compiled in the executable, in production
// it should be set to LVL_NOTICE
 
#define LOG_SHOULD_I( level ) ( level <= LOG_BUILD_LEVEL && level <= log_run_level )


#define LOG(level, fmt, arg...) do {	\
	if ( LOG_SHOULD_I(level) ) { \
		printf("[%s] %s:%d: " fmt "\n", log_level_strings[level], __FUNCTION__,__LINE__, ##arg); \
	} \
} while(0)


#define LL_DEBUG( fmt, arg... ) LOG( LOG_LVL_DEBUG, fmt, ##arg )
#define LL_LOG( fmt, arg... ) LOG( LOG_LVL_LOG, fmt,##arg )
#define LL_NOTICE( fmt,arg... ) LOG( LOG_LVL_NOTICE, fmt, ##arg )
#define LL_WARNING( fmt, arg... ) LOG( LOG_LVL_WARNING, fmt, ##arg )
#define LL_CRITICAL( fmt, arg... ) LOG( LOG_LVL_CRITICAL, fmt, ##arg )

#ifdef	__cplusplus
}
#endif

#endif
