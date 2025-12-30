set(WRAPPER_DIR ${CMAKE_CURRENT_LIST_DIR}/../wrapper)
add_executable(demo_wrapper demo_wrapper.cpp ${WRAPPER_DIR}/pvss.cpp)
target_include_directories(demo_wrapper PRIVATE ${WRAPPER_DIR})
target_link_libraries(demo_wrapper PRIVATE project)
