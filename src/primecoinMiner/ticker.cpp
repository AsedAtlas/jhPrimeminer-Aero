#include "ticker.h"

uint64_t getTimeMilliseconds(void) {
  uint64_t milliseconds = 0;
#if (defined(__MACH__) && defined(__APPLE__))
  struct mach_timebase_info convfact;
  mach_timebase_info(&convfact); // get ticks->nanoseconds conversion factor
  // get time in nanoseconds since computer was booted
  // the measurement is different per core
  uint64_t tick = mach_absolute_time();
  milliseconds = (tick * convfact.numer) / (convfact.denom * 1000000);
#elif defined(_WIN32)
  milliseconds = GetTickCount64();
#elif defined(__unix__)
  struct timespec now;
  clock_gettime(CLOCK_MONOTONIC, &now);
  milliseconds = now.tv_sec*1000 + now.tv_nsec/1000000;
#endif
  return milliseconds;
}

uint64_t getTimeHighRes(void) {
  uint64_t timestamp = 0;
#if (defined(__MACH__) && defined(__APPLE__))
  struct mach_timebase_info convfact;
  mach_timebase_info(&convfact); // get ticks->nanoseconds conversion factor
  // get time in nanoseconds since computer was booted
  // the measurement is different per core
  uint64_t timestamp = mach_absolute_time();
#elif defined(_WIN32)

  LARGE_INTEGER hpc;
  QueryPerformanceCounter(&hpc);
  uint64 timestamp = (uint64)hpc.QuadPart;

#elif defined(__unix__)
  struct timespec now;
  clock_gettime(CLOCK_MONOTONIC, &now);
  timestamp = now.tv_sec;
#endif
  return timestamp;
}

uint64_t getTimerRes(void) {
	uint64_t resolution = 0;
#ifdef WIN32
  LARGE_INTEGER hpcFreq;
  QueryPerformanceFrequency(&hpcFreq);
  return (uint64)hpcFreq.QuadPart;
#else
    struct timespec t_res;
  clock_getres(CLOCK_MONOTONIC, &t_res);
  resolution = t_res.tv_nsec;
  return resolution;
#endif  
}
