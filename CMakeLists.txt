cmake_minimum_required(VERSION 3.20)

# 🎯 【CMake 現代化策略】：解決 FetchContent 的時間戳警告 (CMP0135)
cmake_policy(SET CMP0135 NEW)

project(Kitana_Cryptool CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# =================================================================
# 1. FLTK 現代拉取（FetchContent 純靜態配置）
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
# 2. 建立執行檔與目錄配線
# =================================================================
add_executable(${PROJECT_NAME}
        src/main.cpp
        src/aescrypt.cpp
        src/ui_callbacks.cpp
        src/keygen.cpp
        src/passwdgen.cpp
        src/hashutil.cpp
)

# 註冊全域標頭檔搜尋生命線
target_include_directories(${PROJECT_NAME} PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
)

# =================================================================
# 3. 熔接生命線：咬住 FLTK 核心與影像擴充組件
# =================================================================
# 🎯 升級點：必須同時連結 fltk 與 fltk::images，否則編譯器找不到 Fl_Help_View！
target_link_libraries(${PROJECT_NAME} PRIVATE
        fltk::fltk
        fltk::images
)

# =================================================================
# 4. 跨平台編譯與連結防禦晶片
# =================================================================
if(WIN32)
    # --- Windows 平台 (MSVC & MinGW) ---
    target_include_directories(${PROJECT_NAME} PRIVATE "C:/OpenSSL-MSVC/include")
    target_link_libraries(${PROJECT_NAME} PRIVATE
            "C:/OpenSSL-MSVC/lib/libcrypto.lib"
            "C:/OpenSSL-MSVC/lib/libssl.lib"
            ws2_32 wsock32 crypt32 gdi32 comctl32 ole32 uuid shell32 gdiplus
    )
    if(MSVC)
        # MSVC 特有設定
        target_sources(${PROJECT_NAME} PRIVATE src/resource.rc)
        # WIN32_EXECUTABLE 會自動處理 /SUBSYSTEM:WINDOWS，我們只需要補上 /ENTRY
        set_target_properties(${PROJECT_NAME} PROPERTIES WIN32_EXECUTABLE TRUE)
        target_link_options(${PROJECT_NAME} PRIVATE "/ENTRY:mainCRTStartup")
        target_compile_options(${PROJECT_NAME} PRIVATE "/utf-8")
    elseif(MINGW)
        # MinGW 特有設定
        target_link_options(${PROJECT_NAME} PRIVATE "-mwindows")
    endif()

    # Windows 平台下，自動部署 DLL
    message(STATUS "⚙️ [Kitana Post-Build] Windows 平台：啟動 OpenSSL DLL 自動佈署流水線...")
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
    # --- Linux & other Unix-like 平台 ---
    # 在 Linux 上，我們期望 OpenSSL 是透過系統套件管理器安裝的
    find_package(OpenSSL REQUIRED)
    target_link_libraries(${PROJECT_NAME} PRIVATE OpenSSL::SSL OpenSSL::Crypto Threads::Threads)
endif()


# =================================================================
# 🧪 6. 自動化單元測試流水線 (整合 GoogleTest)
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

# 為測試目標設定跨平台連結
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
    target_link_libraries(Kitana_Tests PRIVATE GTest::gtest_main OpenSSL::SSL OpenSSL::Crypto Threads::Threads)
endif()

include(GoogleTest)
gtest_discover_tests(Kitana_Tests)