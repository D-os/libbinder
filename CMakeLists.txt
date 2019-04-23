include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

add_library(binder SHARED
        "AppOpsManager.cpp"
        "Binder.cpp"
        "BpBinder.cpp"
        "BufferedTextOutput.cpp"
        "Debug.cpp"
        "IActivityManager.cpp"
        "IAppOpsCallback.cpp"
        "IAppOpsService.cpp"
        "IBatteryStats.cpp"
        "IInterface.cpp"
        "IMediaResourceMonitor.cpp"
        "IMemory.cpp"
        "IPCThreadState.cpp"
        "IPermissionController.cpp"
        "IProcessInfoService.cpp"
        "IResultReceiver.cpp"
        "IServiceManager.cpp"
        "IShellCallback.cpp"
        "MemoryBase.cpp"
        "MemoryDealer.cpp"
        "MemoryHeapBase.cpp"
        "Parcel.cpp"
        "PermissionCache.cpp"
        "PersistableBundle.cpp"
        "ProcessInfoService.cpp"
        "ProcessState.cpp"
        "Static.cpp"
        "Status.cpp"
        "TextOutput.cpp"
        "IpPrefix.cpp"
        "Value.cpp"
)
target_link_libraries(binder utils)

add_subdirectory(tests)
