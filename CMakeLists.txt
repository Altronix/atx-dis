cmake_minimum_required(VERSION 3.19)
project(atx-dis)

set(CMAKE_THREAD_PREFER_PTHREAD TRUE)
set(THREADS_PREFER_PTHREAD_FLAG TRUE)
find_package(Threads REQUIRED)

add_executable(atx-dis atx-dis.c log.c json-wrapper.c tiny-json.c watch.c config.c beacon.c)
target_link_libraries(atx-dis Threads::Threads)
install(TARGETS atx-dis RUNTIME DESTINATION bin)