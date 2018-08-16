include_directories(
    "${EXTERNAL_GOOGLETEST_DIR}/googletest/include"
    "${EXTERNAL_GOOGLETEST_DIR}/googlemock/include"
)

add_executable(binderDriverInterfaceTest "binderDriverInterfaceTest.cpp")
target_link_libraries(binderDriverInterfaceTest gtest)

add_executable(binderLibTest "binderLibTest.cpp")
target_link_libraries(binderLibTest binder gtest)

add_executable(binderThroughputTest "binderThroughputTest.cpp")
target_link_libraries(binderThroughputTest binder utils gtest)
