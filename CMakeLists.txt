cmake_minimum_required(VERSION 3.20)

# CMake modernization: address FetchContent timestamp warning (CMP0135)
cmake_policy(SET CMP0135 NEW)

project(Kitana_Cryptool VERSION 0.1 LANGUAGES C CXX)
find_package(Threads REQUIRED)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# =================================================================
# 1. FLTK modern FetchContent (static-only configuration)
# =================================================================
include(FetchContent)
FetchContent_Declare(
        fltk
        GIT_REPOSITORY https://github.com/fltk/fltk.git
        GIT_TAG        release-1.4.0
)
set(FLTK_BUILD_TEST OFF CACHE INTERNAL "")
set(FLTK_BUILD_EXAMPLES OFF CACHE INTERNAL "")
set(FLTK_BUILD_SHARED_LIBS OFF CACHE INTERNAL "")
FetchContent_MakeAvailable(fltk)

# =================================================================
# 2. Create executable and configure directories
# =================================================================
add_executable(${PROJECT_NAME}
        src/main.cpp
        src/aescrypt.cpp
        src/ui_callbacks.cpp
        src/keygen.cpp
        src/passwdgen.cpp
        src/hashutil.cpp
)

# Register global include directory
target_include_directories(${PROJECT_NAME} PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
)

# =================================================================
# 3. Cross-platform build and link configuration
# =================================================================
if(WIN32)
    # --- Windows platform (MSVC & MinGW) ---
    target_include_directories(${PROJECT_NAME} PRIVATE "C:/OpenSSL-MSVC/include")
    
    # --- Windows link libraries ---
    target_link_libraries(${PROJECT_NAME} PRIVATE
            fltk::images # moved to Windows-specific linking
            "C:/OpenSSL-MSVC/lib/libcrypto.lib"
            "C:/OpenSSL-MSVC/lib/libssl.lib"
            ws2_32 wsock32 crypt32 gdi32 comctl32 ole32 uuid shell32 gdiplus
    )
    if(MSVC)
        # MSVC-specific settings
        target_sources(${PROJECT_NAME} PRIVATE src/resource.rc)
        # WIN32_EXECUTABLE handles /SUBSYSTEM:WINDOWS; just add /ENTRY
        set_target_properties(${PROJECT_NAME} PROPERTIES WIN32_EXECUTABLE TRUE)
        target_link_options(${PROJECT_NAME} PRIVATE "/ENTRY:mainCRTStartup")
        target_compile_options(${PROJECT_NAME} PRIVATE "/utf-8")
    elseif(MINGW)
        # MinGW-specific settings
        target_link_options(${PROJECT_NAME} PRIVATE "-mwindows")
    endif()

    # Deploy OpenSSL DLLs on Windows
    message(STATUS "[Kitana Post-Build] Windows platform: starting OpenSSL DLL deployment...")
    set(OPENSSL_DLL_SRC_CRYPTO "C:/OpenSSL-MSVC/bin/libcrypto-3-x64.dll")
    set(OPENSSL_DLL_SRC_SSL    "C:/OpenSSL-MSVC/bin/libssl-3-x64.dll")
    add_custom_command(TARGET ${PROJECT_NAME} POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E copy_if_different
            ${OPENSSL_DLL_SRC_CRYPTO} $<TARGET_FILE_DIR:${PROJECT_NAME}>)

    add_custom_command(TARGET ${PROJECT_NAME} POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E copy_if_different
            ${OPENSSL_DLL_SRC_SSL} $<TARGET_FILE_DIR:${PROJECT_NAME}>)
            
    add_custom_command(TARGET ${PROJECT_NAME} POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E copy_directory
            "${CMAKE_CURRENT_SOURCE_DIR}/licenses" "$<TARGET_FILE_DIR:${PROJECT_NAME}>/licenses")

else()
    # --- Mac & Linux (Unix-like) platform ---
    find_package(OpenSSL REQUIRED)
    
    if(APPLE)
        # 1. Enable the Mac official App bundle shell (App Bundle)
        set_target_properties(${PROJECT_NAME} PROPERTIES 
            MACOSX_BUNDLE TRUE
            MACOSX_BUNDLE_INFO_PLIST "${CMAKE_CURRENT_SOURCE_DIR}/src/Info.plist"
            MACOSX_BUNDLE_ICON_FILE "app.icns"
            OUTPUT_NAME "Kitana_Cryptool"
        )
        
        target_link_libraries(${PROJECT_NAME} PRIVATE fltk::images OpenSSL::SSL OpenSSL::Crypto Threads::Threads)

        # Register app.icns as a Mac bundle resource
        target_sources(${PROJECT_NAME} PRIVATE src/app.icns)
        set_source_files_properties(src/app.icns PROPERTIES MACOSX_BUNDLE_RESOURCES TRUE)

        # 2. 【Complete packaging matrix】: add the final step of "fully automated local re-signing"
        add_custom_command(TARGET ${PROJECT_NAME} POST_BUILD
                COMMAND ${CMAKE_COMMAND} -E copy_directory
                "${CMAKE_CURRENT_SOURCE_DIR}/licenses" "${CMAKE_CURRENT_BINARY_DIR}/Kitana_Cryptool.app/Contents/Resources/licenses"
                COMMAND ${CMAKE_COMMAND} -E copy
                "${CMAKE_CURRENT_SOURCE_DIR}/src/app.png" "${CMAKE_CURRENT_BINARY_DIR}/Kitana_Cryptool.app/Contents/Resources/app.png"
                
                # Agent chip A: fetch, deploy, and fix OpenSSL dynamic library paths
                COMMAND ${CMAKE_COMMAND} -E env 
                ${CMAKE_COMMAND} -DAPP_PATH="${CMAKE_CURRENT_BINARY_DIR}/Kitana_Cryptool.app"
                -P "${CMAKE_CURRENT_SOURCE_DIR}/cmake/MacDeploy.cmake"
                
                # 【Core reinstall protection】: call the Mac built-in codesign to force overwrite re-sign the entire .app internals, fully preventing crashes!
                COMMAND codesign --force --deep --sign - "${CMAKE_CURRENT_BINARY_DIR}/Kitana_Cryptool.app"
        )
        
    else()
        # Linux platform remains unchanged
        target_link_libraries(${PROJECT_NAME} PRIVATE fltk::images OpenSSL::SSL OpenSSL::Crypto Threads::Threads)
        set_target_properties(${PROJECT_NAME} PROPERTIES OUTPUT_NAME "Kitana_Cryptool")
        add_custom_command(TARGET ${PROJECT_NAME} POST_BUILD
                COMMAND ${CMAKE_COMMAND} -E copy_directory
                "${CMAKE_CURRENT_SOURCE_DIR}/licenses" "$<TARGET_FILE_DIR:${PROJECT_NAME}>/licenses"
                COMMAND ${CMAKE_COMMAND} -E copy
                "${CMAKE_CURRENT_SOURCE_DIR}/src/app.png" "$<TARGET_FILE_DIR:${PROJECT_NAME}>/app.png")
    endif()
endif()

# =================================================================
# 4. Automated unit test pipeline (GoogleTest integration)
# =================================================================
enable_testing()
FetchContent_Declare(
        googletest
        URL https://github.com/google/googletest/archive/refs/heads/main.zip
)
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
set(INSTALL_GTEST OFF CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(googletest)

add_executable(Kitana_Tests
        tests/test_main.cpp
        src/aescrypt.cpp
        src/keygen.cpp
        src/passwdgen.cpp
        src/hashutil.cpp
)

target_include_directories(Kitana_Tests PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
)

# Cross-platform linking for the test target
if(WIN32)
    target_include_directories(Kitana_Tests PRIVATE "C:/OpenSSL-MSVC/include")
    target_link_libraries(Kitana_Tests PRIVATE GTest::gtest_main
            "C:/OpenSSL-MSVC/lib/libcrypto.lib"
            "C:/OpenSSL-MSVC/lib/libssl.lib"
            ws2_32 crypt32
    )
    if(MSVC)
        target_compile_options(Kitana_Tests PRIVATE "/utf-8")
    endif()
    add_custom_command(TARGET Kitana_Tests POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "C:/OpenSSL-MSVC/bin/libcrypto-3-x64.dll" $<TARGET_FILE_DIR:Kitana_Tests>)
    add_custom_command(TARGET Kitana_Tests POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "C:/OpenSSL-MSVC/bin/libssl-3-x64.dll" $<TARGET_FILE_DIR:Kitana_Tests>)
else()
    target_link_libraries(Kitana_Tests PRIVATE 
        GTest::gtest_main 
        OpenSSL::SSL 
        OpenSSL::Crypto 
        Threads::Threads
)
endif()

include(GoogleTest)
gtest_discover_tests(Kitana_Tests)