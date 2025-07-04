# CMake build script for the NetnsDhcpSimulator project.
# This is the final, corrected version for the multi-file architecture.

cmake_minimum_required(VERSION 3.10)
project(NetnsDhcpSimulator C)

# --- Project Settings ---
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(TARGET_NAME netns_sim)

# --- Define Source Files ---
# THIS IS THE FIX: The filenames now correctly match the files we created.
set(SRCS
    src/main.c
    src/netns_manager.c
    src/dhcp_client.c
    src/dhcp_protocol_v4.c   # Corrected filename
    src/dhcp_protocol_v6.c   # Corrected filename
)

# --- Define the Executable Target ---
add_executable(${TARGET_NAME} ${SRCS})

# --- Apply Properties to the Target ---

# Add compiler options for warnings and debugging symbols.
target_compile_options(${TARGET_NAME} PRIVATE -Wall -Wextra -g)

# Add our own source directory to the include path for local headers.
target_include_directories(${TARGET_NAME} PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
)

# Explicitly and directly link the required libraries by name.
target_link_libraries(${TARGET_NAME} PRIVATE nl-3 nl-route-3)

# --- Custom Build Step ---
# This command runs after the executable is built. It copies the
# 'conf' directory into the build output directory, which is needed
# by the C program to find the Kea configuration files.
add_custom_command(
    TARGET ${TARGET_NAME} POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_directory
        "${CMAKE_SOURCE_DIR}/conf"
        "$<TARGET_FILE_DIR:${TARGET_NAME}>/conf"
    COMMENT "Copying configuration files"
)