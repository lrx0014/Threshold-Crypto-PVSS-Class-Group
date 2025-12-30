add_library(pvss_wrapper STATIC pvss.cpp)

target_include_directories(pvss_wrapper
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}
)

target_link_libraries(pvss_wrapper
    PUBLIC
        project
)

# Export headers to wrapper/dist/include and library to wrapper/dist/lib
set(WRAPPER_DIST_INCLUDE ${CMAKE_CURRENT_SOURCE_DIR}/dist/include)
set(WRAPPER_DIST_LIB ${CMAKE_CURRENT_SOURCE_DIR}/dist/lib)

add_custom_command(TARGET pvss_wrapper POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E make_directory ${WRAPPER_DIST_INCLUDE}
    COMMAND ${CMAKE_COMMAND} -E make_directory ${WRAPPER_DIST_LIB}
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
            ${CMAKE_CURRENT_SOURCE_DIR}/pvss.h
            ${WRAPPER_DIST_INCLUDE}/pvss.h
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
            $<TARGET_FILE:pvss_wrapper>
            ${WRAPPER_DIST_LIB}/$<TARGET_FILE_NAME:pvss_wrapper>
    VERBATIM
)
