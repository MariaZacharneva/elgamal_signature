cmake_minimum_required(VERSION 3.28)
project(elgamal_clion)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)
set(CMAKE_AUTOUIC ON)


find_package(Qt6 COMPONENTS
        Core
        Gui
        Widgets
        REQUIRED)

add_executable(elgamal_clion main.cpp
        src/view/view.cpp
        src/view/view.h
        src/view/sign_view.h
        src/view/verify_view.h
        src/view/verify_view.cpp
        src/view/sign_view.cpp
        src/cryptography/signature.h
        src/view/abstract_view.h
        src/cryptography/cryptography.cpp
        src/cryptography/cryptography.h
        src/cryptography/tools.cpp
        src/cryptography/tools.h)

target_link_libraries(elgamal_clion
        Qt::Core
        Qt::Gui
        Qt::Widgets
)

set(BOOST_ROOT "C:/Program Files/boost_1_82_0")

find_package(Boost 1.82.0 REQUIRED)

if (NOT Boost_FOUND)
    message(FATAL_ERROR "Could not find boost!")
endif ()
include_directories(${Boost_INCLUDE_DIR})

if (WIN32 AND NOT DEFINED CMAKE_TOOLCHAIN_FILE)
    set(DEBUG_SUFFIX)
    if (MSVC AND CMAKE_BUILD_TYPE MATCHES "Debug")
        set(DEBUG_SUFFIX "d")
    endif ()
    set(QT_INSTALL_PATH "${CMAKE_PREFIX_PATH}")
    if (NOT EXISTS "${QT_INSTALL_PATH}/bin")
        set(QT_INSTALL_PATH "${QT_INSTALL_PATH}/..")
        if (NOT EXISTS "${QT_INSTALL_PATH}/bin")
            set(QT_INSTALL_PATH "${QT_INSTALL_PATH}/..")
        endif ()
    endif ()
    if (EXISTS "${QT_INSTALL_PATH}/plugins/platforms/qwindows${DEBUG_SUFFIX}.dll")
        add_custom_command(TARGET ${PROJECT_NAME} POST_BUILD
                COMMAND ${CMAKE_COMMAND} -E make_directory
                "$<TARGET_FILE_DIR:${PROJECT_NAME}>/plugins/platforms/")
        add_custom_command(TARGET ${PROJECT_NAME} POST_BUILD
                COMMAND ${CMAKE_COMMAND} -E copy
                "${QT_INSTALL_PATH}/plugins/platforms/qwindows${DEBUG_SUFFIX}.dll"
                "$<TARGET_FILE_DIR:${PROJECT_NAME}>/plugins/platforms/")
    endif ()
    foreach (QT_LIB Core Gui Widgets)
        add_custom_command(TARGET ${PROJECT_NAME} POST_BUILD
                COMMAND ${CMAKE_COMMAND} -E copy
                "${QT_INSTALL_PATH}/bin/Qt6${QT_LIB}${DEBUG_SUFFIX}.dll"
                "$<TARGET_FILE_DIR:${PROJECT_NAME}>")
    endforeach (QT_LIB)
endif ()

add_subdirectory(test)

qt_add_resources(elgamal_clion "images" PREFIX "/images" FILES icon.png)