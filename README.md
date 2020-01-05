## 前言
本文代码基于Android 10.0.0 r16 具体代码将上传到我的[github仓库](https://github.com/ContentPane/Android-Q-Zygote)

在Android中，所有应用程序的进程和系统服务的进程都是由Zygote进程通过fork子进程产生的，Zygote进程包含着已经预加载的资源和虚拟机，所以通过`fork`出来的子进程也天生具有Zygote进程的所有东西，减轻了每次系统新建进程时的压力。

![](https://user-gold-cdn.xitu.io/2020/1/1/16f5cb6638ea7126?w=1095&h=960&f=png&s=439668)
[图源来自Gityuan](http://gityuan.com/android/)

可以看出Zygote连接了Native层也就是C/C++层和Java Framework层，作为接下来所有创建的线程的爸爸，Zygote自带已经加载好的Java虚拟机，class资源，jni运行环境等,真正的一人之下(init进程)，万人之上(AMS，ATMS，WMS等)。`fork`子进程的时候子进程就获得了父进程的一份资源副本，然后就开始脱离父进程运行。所以打开一个app即创建一个进程只需要几百毫秒的时间。
## Zygote是如何被启动的
在system/core/rootdir目录下有不同的配置文件，他们是由Android初始化语言(Android Init Language)编写的脚本，具体语法可以查看[相关文章](https://blog.csdn.net/xusiwei1236/article/details/41577231)，primaryZygote和secondaryZygote分别对应主模式和副模式，例如`init.zygote64_32.rc`，这里主模式就是64位，副模式则是32位。
目前来说一共有以下四个rc文件:
- init.zygote32.rc
- init.zygote32_64.rc
- init.zygote64.rc
- init.zygote64_32.rc
   
![init.zygote64_32.rc](https://user-gold-cdn.xitu.io/2019/12/31/16f5a3cebc824647?w=205&h=99&f=png&s=6703init.zygote64_32.rc)



这里以zygote64_32.rc为例 源码如下:
/system/core/rootdir/init.zygote64_32.rc
```
service zygote /system/bin/app_process64 -Xzygote /system/bin --zygote --start-system-server --socket-name=zygote
class main
priority -20
user root
group root readproc reserved_disk
// 660 权限 只有拥有者有读写权限；而属组用户和其他用户只有读权限。
socket zygote stream 660 root system
socket usap_pool_primary stream 660 root system
onrestart write /sys/android_power/request_state wake
onrestart write /sys/power/state on
onrestart restart audioserver
onrestart restart cameraserver
onrestart restart media
onrestart restart netd
onrestart restart wificond
// 创建子进程时，向 /dev/cpuset/foreground/tasks 写入pid
writepid /dev/cpuset/foreground/tasks

    
service zygote_secondary /system/bin/app_process32 -Xzygote /system/bin --zygote --socket-name=zygote_secondary --enable-lazy-preload
class main
priority -20
user root
group root readproc reserved_disk
socket zygote_secondary stream 660 root system
socket usap_pool_secondary stream 660 root system
onrestart restart zygote
writepid /dev/cpuset/foreground/tasks
```
上面的脚本大概的意思就是，通过`Service`命令创建zygote进程，zygote进程对应的路径为system/bin/app_process64，启动的入口即是`class main`所指的main函数，而app_process64对应的代码定义在`app_main.cpp`中。

### app_main.cpp
下面我们选出一些`app_main.cpp`中关键的代码来看

/frameworks/base/cmds/app_process/app_main.cpp
```java
int main(int argc, char* const argv[])
{
    ...
    // 1
    if (zygote) {
        runtime.start("com.android.internal.os.ZygoteInit", args, zygote);
    } else if (className) {
        runtime.start("com.android.internal.os.RuntimeInit", args, zygote);
    } else {
        fprintf(stderr, "Error: no class name or --zygote supplied.\n");
        app_usage();
        LOG_ALWAYS_FATAL("app_process: no class name or --zygote supplied.");
    }
}
```
如注释1所描述的这里的`runtime`为`AppRuntime`类型，而`AppRuntime`又继承于`AndroidRuntime`，`AppRuntime`中并没有重写父类的`start()`方法，所以这里`start()`方法调用的是`AndroidRuntime`的`start()`方法。

### AndroidRuntime.cpp
我们再来看看父类`AndroidRuntime.cpp`实现的`start()`方法
```C++
void AndroidRuntime::start(const char* className, const Vector<String8>& options, bool zygote)
{
    // 开机时如果没看到这个log的话可能在Zygote初始化时发生错误
    ALOGD(">>>>>> START %s uid %d <<<<<<\n",
            className != NULL ? className : "(unknown)", getuid());
            
    ...
    /* start the virtual machine */
    JniInvocation jni_invocation;
    jni_invocation.Init(NULL);
    JNIEnv* env;
    // 开启Java虚拟机
    if (startVm(&mJavaVM, &env, zygote) != 0) {
        return;
    }
    onVmCreated(env);

    /*
     * Register android functions.
     */
     // Java虚拟机注册JNI方法
    if (startReg(env) < 0) {
        ALOGE("Unable to register all android natives\n");
        return;
    }

    /*
     * We want to call main() with a String array with arguments in it.
     * At present we have two arguments, the class name and an option string.
     * Create an array to hold them.
     */
    jclass stringClass;
    jobjectArray strArray;
    jstring classNameStr;
    
    // classNameStr是传入的参数className转化而来，值为com.android.internal.os.ZygoteInit
    stringClass = env->FindClass("java/lang/String");
    assert(stringClass != NULL);
    strArray = env->NewObjectArray(options.size() + 1, stringClass, NULL);
    assert(strArray != NULL);
    classNameStr = env->NewStringUTF(className);
    assert(classNameStr != NULL);
    env->SetObjectArrayElement(strArray, 0, classNameStr);

    for (size_t i = 0; i < options.size(); ++i) {
        jstring optionsStr = env->NewStringUTF(options.itemAt(i).string());
        assert(optionsStr != NULL);
        env->SetObjectArrayElement(strArray, i + 1, optionsStr);
    }

    /*
     * Start VM.  This thread becomes the main thread of the VM, and will
     * not return until the VM exits.
     */
     // 将className的"."替换为"/" 这里为ZygoteInit类
     // 替换之后为com/android/internal/os/ZygoteInit
    char* slashClassName = toSlashClassName(className != NULL ? className : "");
    jclass startClass = env->FindClass(slashClassName);
    if (startClass == NULL) {
        ALOGE("JavaVM unable to locate class '%s'\n", slashClassName);
        /* keep going */
    } else {
        // 找到ZygoteInit的main()方法
        jmethodID startMeth = env->GetStaticMethodID(startClass, "main",
            "([Ljava/lang/String;)V");
        if (startMeth == NULL) {
            ALOGE("JavaVM unable to find main() in '%s'\n", className);
            /* keep going */
        } else {
            // 调用ZygoteInit的main()方法
            // 从Native层进入了Java层
            env->CallStaticVoidMethod(startClass, startMeth, strArray);

#if 0
            if (env->ExceptionCheck())
                threadExitUncaughtException(env);
#endif
        }
    }
    free(slashClassName);

    ALOGD("Shutting down VM\n");
    if (mJavaVM->DetachCurrentThread() != JNI_OK)
        ALOGW("Warning: unable to detach main thread\n");
    if (mJavaVM->DestroyJavaVM() != 0)
        ALOGW("Warning: VM did not shut down cleanly\n");
}

```


### ZygoteInit.java
从这里开始就进入了Java层,从前面的`runtime.start("com.android.internal.os.ZygoteInit", args, zygote);`可知最后通过反射调用了`ZygoteInit.main()`
我们再来看看这个`ZygoteInit.main()`又是什么。

frameworks/base/core/java/com/android/internal/os/ZygoteInit.java
```Java
@UnsupportedAppUsage
public static void main(String argv[]) {
    ZygoteServer zygoteServer = null;

    // 确保创建线程会抛出异常 因为Zygote初始化时是单线程运行的
    ZygoteHooks.startZygoteNoThreadCreation();

    // Zygote goes into its own process group.
    try {
        Os.setpgid(0, 0);
    } catch (ErrnoException ex) {
        throw new RuntimeException("Failed to setpgid(0,0)", ex);
    }

    Runnable caller;
    try {
        // 记录Zygote的启动时间
        if (!"1".equals(SystemProperties.get("sys.boot_completed"))) {
            MetricsLogger.histogram(null, "boot_zygote_init",
                    (int) SystemClock.elapsedRealtime());
        }

        ...
        // 打开DDMS
        RuntimeInit.enableDdms();

        boolean startSystemServer = false;
        // 定义了zygote socket名为zygote 简单的初始化 后面可能会重新赋值
        String zygoteSocketName = "zygote";
        String abiList = null;
        boolean enableLazyPreload = false;
        for (int i = 1; i < argv.length; i++) {
            // init.zygote64_32.rc的参数传到这里了
            if ("start-system-server".equals(argv[i])) {
                startSystemServer = true;
            } else if ("--enable-lazy-preload".equals(argv[i])) {
                enableLazyPreload = true;
            } else if (argv[i].startsWith(ABI_LIST_ARG)) {
                // app_main.cpp 读取abi list的文件然后append到参数中 在这里解析
                abiList = argv[i].substring(ABI_LIST_ARG.length());
            } else if (argv[i].startsWith(SOCKET_NAME_ARG)) {
                // socketName也在app_main.cpp中被设置
                zygoteSocketName = argv[i].substring(SOCKET_NAME_ARG.length());
            } else {
                throw new RuntimeException("Unknown command line argument: " + argv[i]);
            }
        }
        
        // Zygote.PRIMARY_SOCKET_NAME = "zygote";
        final boolean isPrimaryZygote = zygoteSocketName.equals(Zygote.PRIMARY_SOCKET_NAME);

        if (abiList == null) {
            throw new RuntimeException("No ABI list supplied.");
        }

        // In some configurations, we avoid preloading resources and classes eagerly.
        // In such cases, we will preload things prior to our first fork.
        if (!enableLazyPreload) {
            bootTimingsTraceLog.traceBegin("ZygotePreload");
            EventLog.writeEvent(LOG_BOOT_PROGRESS_PRELOAD_START, SystemClock.uptimeMillis());
            // preload方法在下面展开
            preload(bootTimingsTraceLog);
            EventLog.writeEvent(LOG_BOOT_PROGRESS_PRELOAD_END,
                    SystemClock.uptimeMillis());
            bootTimingsTraceLog.traceEnd(); // ZygotePreload
        } else {
            // Thread.currentThread().setPriority(Thread.NORM_PRIORITY);
            // 设置线程优先级为NORM_PRIORITY = 5;
            Zygote.resetNicePriority();
        }

        // Do an initial gc to clean up after startup
        bootTimingsTraceLog.traceBegin("PostZygoteInitGC");
        // 回收一些前面预加载资源的内存
        gcAndFinalize();
        bootTimingsTraceLog.traceEnd(); // PostZygoteInitGC

        bootTimingsTraceLog.traceEnd(); // ZygoteInit
        
        // 关闭日志跟踪 后面fork进程就不会有之前的日志记录了
        Trace.setTracingEnabled(false, 0);


        Zygote.initNativeState(isPrimaryZygote);
        
        // 从这里开始可以创建新线程了
        ZygoteHooks.stopZygoteNoThreadCreation();
        
        // 创建Server端等待之后的AMS等进程连接
        zygoteServer = new ZygoteServer(isPrimaryZygote);

        if (startSystemServer) {
            // 先fork一个SystemServer进程出来
            // 在下面展开
            // 这里的r其实就是handleSystemServerProcess()方法
            Runnable r = forkSystemServer(abiList, zygoteSocketName, zygoteServer);

            // {@code r == null} in the parent (zygote) process, and {@code r != null} in the
            // child (system_server) process.
            if (r != null) {
                r.run();
                return;
            }
        }

        Log.i(TAG, "Accepting command socket connections");

        // 阻塞等待客户端连接请求
        caller = zygoteServer.runSelectLoop(abiList);
    } catch (Throwable ex) {
        Log.e(TAG, "System zygote died with exception", ex);
        throw ex;
    } finally {
        if (zygoteServer != null) {
            zygoteServer.closeServerSocket();
        }
    }

    // 子进程执行返回的caller对象 
    // 父进程只会阻塞获取连接请求或者处理fork请求
    if (caller != null) {
        caller.run();
    }
}

static void preload(TimingsTraceLog bootTimingsTraceLog) {
    Log.d(TAG, "begin preload");
    bootTimingsTraceLog.traceBegin("BeginPreload");
    beginPreload();
    bootTimingsTraceLog.traceEnd(); // BeginPreload
    bootTimingsTraceLog.traceBegin("PreloadClasses");
    // 加载/system/etc/preloaded-classes目录下的class文件
    preloadClasses();
    bootTimingsTraceLog.traceEnd(); // PreloadClasses
    bootTimingsTraceLog.traceBegin("CacheNonBootClasspathClassLoaders");
    // 加载许多应用程序使用但不能放在启动类路径中的内容。
    // 这里主要加载两个jar文件
    // /system/framework/android.hidl.base-V1.0-java.jar
    // /system/framework/android.hidl.manager-V1.0-java.jar
    cacheNonBootClasspathClassLoaders();
    bootTimingsTraceLog.traceEnd(); // CacheNonBootClasspathClassLoaders
    bootTimingsTraceLog.traceBegin("PreloadResources");
    // 加载一些资源文件
    // R.array.preloaded_drawables R.array.preloaded_color_state_lists等
    preloadResources();
    bootTimingsTraceLog.traceEnd(); // PreloadResources
    Trace.traceBegin(Trace.TRACE_TAG_DALVIK, "PreloadAppProcessHALs");
    // 最终调用 frameworks/native/libs/ui/GraphicBufferMapper.cpp的preloadHal()方法
    nativePreloadAppProcessHALs();
    Trace.traceEnd(Trace.TRACE_TAG_DALVIK);
    Trace.traceBegin(Trace.TRACE_TAG_DALVIK, "PreloadGraphicsDriver");
    // 通过一定的条件判断后决定调用navtive层frameworks/native/opengl/libagl/egl.cpp 的eglGetDisplay方法
    maybePreloadGraphicsDriver();
    Trace.traceEnd(Trace.TRACE_TAG_DALVIK);
    // 加载一些共享库 android compiler_rt jnigraphics
    preloadSharedLibraries();
    // 设置文字的一些效果以缓存文字描绘
    // 在native层做一些初始化 frameworks/base/core/jni/android_text_Hyphenator.cpp init()方法
    preloadTextResources();
    // Ask the WebViewFactory to do any initialization that must run in the zygote process,
    // for memory sharing purposes.
    // 加载webviewchromium_loader库
    WebViewFactory.prepareWebViewInZygote();
    // 转换为软引用 让 Zygote GC时可以回收
    // 即调用gcAndFinalize()方法的时候
    endPreload();
    warmUpJcaProviders();
    Log.d(TAG, "end preload");

    sPreloadComplete = true;
}

private static Runnable forkSystemServer(String abiList, String socketName,
        ZygoteServer zygoteServer) {
    ...
    /* Hardcoded command line to start the system server */
    String args[] = {
            "--setuid=1000",
            "--setgid=1000",
            "--setgroups=1001,1002,1003,1004,1005,1006,1007,1008,1009,1010,1018,1021,1023,"
                    + "1024,1032,1065,3001,3002,3003,3006,3007,3009,3010",
            "--capabilities=" + capabilities + "," + capabilities,
            "--nice-name=system_server",
            "--runtime-args",
            "--target-sdk-version=" + VMRuntime.SDK_VERSION_CUR_DEVELOPMENT,
            "com.android.server.SystemServer",
    };
    ZygoteArguments parsedArgs = null;

    int pid;

    try {
        parsedArgs = new ZygoteArguments(args);
        Zygote.applyDebuggerSystemProperty(parsedArgs);
        Zygote.applyInvokeWithSystemProperty(parsedArgs);

        boolean profileSystemServer = SystemProperties.getBoolean(
                "dalvik.vm.profilesystemserver", false);
        if (profileSystemServer) {
            parsedArgs.mRuntimeFlags |= Zygote.PROFILE_SYSTEM_SERVER;
        }

        // fork SystemServer进程
        // 调用native方法 nativeForkSystemServer()
        pid = Zygote.forkSystemServer(
                parsedArgs.mUid, parsedArgs.mGid,
                parsedArgs.mGids,
                parsedArgs.mRuntimeFlags,
                null,
                parsedArgs.mPermittedCapabilities,
                parsedArgs.mEffectiveCapabilities);
    } catch (IllegalArgumentException ex) {
        throw new RuntimeException(ex);
    }

    // pid为0则为子进程 pid > 0为父进程
    // 父进程返回子进程的pid
    if (pid == 0) {
        if (hasSecondZygote(abiList)) {
            waitForSecondaryZygote(socketName);
        }
        //关闭socket端口
        zygoteServer.closeServerSocket();
        return handleSystemServerProcess(parsedArgs);
    }

    return null;
}
```
### com_android_internal_os_Zygote.cpp
最后我们来说一下这个nativeForkSystemServer()的方法,看看Zygote是怎么把SystemServer的进程fork出来的。

/frameworks/base/core/jni/com_android_internal_os_Zygote.cpp
```C++
static jint com_android_internal_os_Zygote_nativeForkSystemServer(
        JNIEnv* env, jclass, uid_t uid, gid_t gid, jintArray gids,
        jint runtime_flags, jobjectArray rlimits, jlong permitted_capabilities,
        jlong effective_capabilities) {
  // 一个vector是子进程需要关闭的fd 这是属于Zygote自己的fd
  // 而另一个vector存的是
  // 在第一次fork的时候创建一个fd table 否则每次fork需要检查里面的fd是否正常 
  std::vector<int> fds_to_close(MakeUsapPipeReadFDVector()),
                   fds_to_ignore(fds_to_close);

  fds_to_close.push_back(gUsapPoolSocketFD);

  if (gUsapPoolEventFD != -1) {
    fds_to_close.push_back(gUsapPoolEventFD);
    fds_to_ignore.push_back(gUsapPoolEventFD);
  }
  
  // 里面调用fork()函数
  pid_t pid = ForkCommon(env, true,
                         fds_to_close,
                         fds_to_ignore);
  // 子进程                       
  if (pid == 0) {
      SpecializeCommon(env, uid, gid, gids, runtime_flags, rlimits,
                       permitted_capabilities, effective_capabilities,
                       MOUNT_EXTERNAL_DEFAULT, nullptr, nullptr, true,
                       false, nullptr, nullptr);
  } else if (pid > 0) {
      // The zygote process checks whether the child process has died or not.
      ALOGI("System server process %d has been created", pid);
      gSystemServerPid = pid;
      int status;
      // 检查一下子线程这时候有没有发生错误
      // WNOHANG 为非阻塞模式的option 如果发生错误则返回子线程的pid 没发生错误返回0
      if (waitpid(pid, &status, WNOHANG) == pid) {
          ALOGE("System server process %d has died. Restarting Zygote!", pid);
          RuntimeAbort(env, __LINE__, "System server process has died. Restarting Zygote!");
      }

      if (UsePerAppMemcg()) {
          // Assign system_server to the correct memory cgroup.
          // Not all devices mount memcg so check if it is mounted first
          // to avoid unnecessarily printing errors and denials in the logs.
          if (!SetTaskProfiles(pid, std::vector<std::string>{"SystemMemoryProcess"})) {
              ALOGE("couldn't add process %d into system memcg group", pid);
          }
      }
  }
  return pid;
}

static pid_t ForkCommon(JNIEnv* env, bool is_system_server,
                        const std::vector<int>& fds_to_close,
                        const std::vector<int>& fds_to_ignore) {
  ...
  pid_t pid = fork();

  if (pid == 0) {
    // The child process.
    PreApplicationInit();

    // 关掉所有fds_to_close中的fd
    DetachDescriptors(env, fds_to_close, fail_fn);

    // Invalidate the entries in the USAP table.
    ClearUsapTable();

    // Re-open all remaining open file descriptors so that they aren't shared
    // with the zygote across a fork.
    gOpenFdTable->ReopenOrDetach(fail_fn);

    // Turn fdsan back on.
    android_fdsan_set_error_level(fdsan_error_level);
  } else {
    ALOGD("Forked child process %d", pid);
  }

  // We blocked SIGCHLD prior to a fork, we unblock it here.
  UnblockSignal(SIGCHLD, fail_fn);

  return pid;
}
```
### ZygoteServer.java
Zygote自己的启动过程和Zygote启动SystemServer进程到这里就说得差不多了，我们最后再来同场加映一下这个ZygoteServer的`runSelectLoop()`方法，这个方法是干嘛的呢？主要是接受AMS，ATMS等系统服务进程作为Client端经过socket通信，向ZygoteServer申请`fork()`新的进程，处理这些请求用的。这个方法是一个阻塞方法，父进程不会有返回值，子进程才会返回一个Runnable。

frameworks/base/core/java/com/android/internal/os/ZygoteServer.java
```Java
Runnable runSelectLoop(String abiList) {
        ArrayList<FileDescriptor> socketFDs = new ArrayList<FileDescriptor>();
        ArrayList<ZygoteConnection> peers = new ArrayList<ZygoteConnection>();
        
        // 第一个元素存自己作为Server端的fd
        // 其实它就是ZygoteServer的管家，你要申请fork子进程必须在这个Socket中申请注册
        // 注册完成后才能申请fork子进程
        socketFDs.add(mZygoteSocket.getFileDescriptor());
        // 相应的就在对应的connection数组加一个null 
        // 因为这时候还没有请求连接的Connection
        peers.add(null);

        while (true) {
            // 获取UsapPool的最大/最小连接值 重新填充的阈值 
            // 还有每隔一段时间检查配置文件去更新这些值
            fetchUsapPoolPolicyPropsWithMinInterval();
            
            // 存储usapPool的fd
            int[] usapPipeFDs = null;
            // 通信连接用的StructPollfd结构数组
            StructPollfd[] pollFDs = null;

            // Allocate enough space for the poll structs, taking into account
            // the state of the USAP pool for this Zygote (could be a
            // regular Zygote, a WebView Zygote, or an AppZygote).
            if (mUsapPoolEnabled) {
                // 拿到活跃的usap socket fd
                // 调用的是native层的MakeUsapPipeReadFDVector()函数
                usapPipeFDs = Zygote.getUsapPipeFDs();
                // 这里加的1是为了下面有一个新建的StructPollfd usapPoolEventFd腾出来的空间
                // 可以看下面注释2
                pollFDs = new StructPollfd[socketFDs.size() + 1 + usapPipeFDs.length];
            } else {
                pollFDs = new StructPollfd[socketFDs.size()];
            }

            /*
             * For reasons of correctness the USAP pool pipe and event FDs
             * must be processed before the session and server sockets.  This
             * is to ensure that the USAP pool accounting information is
             * accurate when handling other requests like API blacklist
             * exemptions.
             */

            int pollIndex = 0;
            // 遍历已经存储好的fd
            for (FileDescriptor socketFD : socketFDs) {
                pollFDs[pollIndex] = new StructPollfd();
                pollFDs[pollIndex].fd = socketFD;
                // POLLIN即为可读状态
                pollFDs[pollIndex].events = (short) POLLIN;
                ++pollIndex;
            }
            
            final int usapPoolEventFDIndex = pollIndex;
            
            // 2
            if (mUsapPoolEnabled) {
                // 上面腾出了一个位置放置这个StructPollfd
                pollFDs[pollIndex] = new StructPollfd();
                pollFDs[pollIndex].fd = mUsapPoolEventFD;
                pollFDs[pollIndex].events = (short) POLLIN;
                ++pollIndex;
                
                // 然后把活跃的usap socket fd依次放到后面
                for (int usapPipeFD : usapPipeFDs) {
                    FileDescriptor managedFd = new FileDescriptor();
                    managedFd.setInt$(usapPipeFD);

                    pollFDs[pollIndex] = new StructPollfd();
                    pollFDs[pollIndex].fd = managedFd;
                    pollFDs[pollIndex].events = (short) POLLIN;
                    ++pollIndex;
                }
            }

            try {
                // 这里阻塞获取事件 主要原理是Linux的I/O复用技术
                Os.poll(pollFDs, -1);
            } catch (ErrnoException ex) {
                throw new RuntimeException("poll failed", ex);
            }
            
            // 标记是否需要填充usapPool
            boolean usapPoolFDRead = false;

            while (--pollIndex >= 0) {
                if ((pollFDs[pollIndex].revents & POLLIN) == 0) {
                    continue;
                }
                
                // 等于0即为ZygoteSever自身的socket 用来处理连接请求
                // 然后存入peers即ZygoteConnection的数组中
                // 其实就是系统服务在ZygoteServer这里注册的过程
                if (pollIndex == 0) {
                    // Zygote server socket

                    ZygoteConnection newPeer = acceptCommandPeer(abiList);
                    peers.add(newPeer);
                    socketFDs.add(newPeer.getFileDescriptor());

                } else if (pollIndex < usapPoolEventFDIndex) {
                    // Session socket accepted from the Zygote server socket
                    // ZygoteServer已经连接好的的fd
                    // 其实这里就是看看有没有socket发出fork子进程请求的过程
                    try {
                        ZygoteConnection connection = peers.get(pollIndex);
                        // 3
                        // 这里就是处理fork子进程请求的地方
                        final Runnable command = connection.processOneCommand(this);

                        // TODO (chriswailes): Is this extra check necessary?
                        // mIsForkChild是由子进程设置的，在forkAndSpecialize()方法之后
                        if (mIsForkChild) {
                            // We're in the child. We should always have a command to run at this
                            // stage if processOneCommand hasn't called "exec".
                            if (command == null) {
                                throw new IllegalStateException("command == null");
                            }

                            return command;
                        } else {
                            // We're in the server - we should never have any commands to run.
                            if (command != null) {
                                throw new IllegalStateException("command != null");
                            }

                            // We don't know whether the remote side of the socket was closed or
                            // not until we attempt to read from it from processOneCommand. This
                            // shows up as a regular POLLIN event in our regular processing loop.
                            // 检测这个connection是否关闭了，如果关闭就从数组中移除
                            // 防止下次再读这个connection的时候已经关闭了
                            if (connection.isClosedByPeer()) {
                                connection.closeSocket();
                                peers.remove(pollIndex);
                                socketFDs.remove(pollIndex);
                            }
                        }
                    } catch (Exception e) {
                        if (!mIsForkChild) {
                            // We're in the server so any exception here is one that has taken place
                            // pre-fork while processing commands or reading / writing from the
                            // control socket. Make a loud noise about any such exceptions so that
                            // we know exactly what failed and why.

                            Slog.e(TAG, "Exception executing zygote command: ", e);

                            // Make sure the socket is closed so that the other end knows
                            // immediately that something has gone wrong and doesn't time out
                            // waiting for a response.
                            ZygoteConnection conn = peers.remove(pollIndex);
                            conn.closeSocket();

                            socketFDs.remove(pollIndex);
                        } else {
                            // We're in the child so any exception caught here has happened post
                            // fork and before we execute ActivityThread.main (or any other main()
                            // method). Log the details of the exception and bring down the process.
                            Log.e(TAG, "Caught post-fork exception in child process.", e);
                            throw e;
                        }
                    } finally {
                        // Reset the child flag, in the event that the child process is a child-
                        // zygote. The flag will not be consulted this loop pass after the Runnable
                        // is returned.
                        mIsForkChild = false;
                    }
                } else {
                    // Either the USAP pool event FD or a USAP reporting pipe.

                    // 如果这是event FD，那这个值就是USAPs被清除的数量
                    // 如果这是reporting pipe FD，那这个值就是其对应的PID
                    long messagePayload = -1;
                    
                    // 剩下的就是usapPool连接池的Fd
                    try {
                        byte[] buffer = new byte[Zygote.USAP_MANAGEMENT_MESSAGE_BYTES];
                        int readBytes = Os.read(pollFDs[pollIndex].fd, buffer, 0, buffer.length);

                        if (readBytes == Zygote.USAP_MANAGEMENT_MESSAGE_BYTES) {
                            DataInputStream inputStream =
                                    new DataInputStream(new ByteArrayInputStream(buffer));

                            messagePayload = inputStream.readLong();
                        } else {
                            Log.e(TAG, "Incomplete read from USAP management FD of size "
                                    + readBytes);
                            continue;
                        }
                    } catch (Exception ex) {
                        if (pollIndex == usapPoolEventFDIndex) {
                            Log.e(TAG, "Failed to read from USAP pool event FD: "
                                    + ex.getMessage());
                        } else {
                            Log.e(TAG, "Failed to read from USAP reporting pipe: "
                                    + ex.getMessage());
                        }

                        continue;
                    }
                    
                    // 把这个fd对应pid 从 UsapTableEntry 清理掉
                    if (pollIndex > usapPoolEventFDIndex) {
                        Zygote.removeUsapTableEntry((int) messagePayload);
                    }
                    
                    // 重新填充usapPool
                    usapPoolFDRead = true;
                }
            }

            // Check to see if the USAP pool needs to be refilled.
            // 如果UsapPool连接池需要填充 
            // 则新建socket fd填充至阈值
            if (usapPoolFDRead) {
                int[] sessionSocketRawFDs =
                        socketFDs.subList(1, socketFDs.size())
                                .stream()
                                .mapToInt(fd -> fd.getInt$())
                                .toArray();

                final Runnable command = fillUsapPool(sessionSocketRawFDs);
                
                // 把填充方法fillUsapPool()作为runnable返回
                if (command != null) {
                    return command;
                }
            }
        }
    }

```
runSelectLoop最主要的核心点就是注释3所标注的`processOneCommand()`方法，用来处理服务进程`fork()`子进程的请求，这个方法具体会在下一篇文章给大家分析，这篇文章写到这里是有点长了。看完上面的`runSelectLoop()`方法觉得不太懂或者想了解底层原理的同学可以看一下一下这三篇关于Linux的I/O的文章，看完这三篇文章基本上就可以对Linux的I/O模型有一定的了解了。
- [聊聊同步、异步、阻塞与非阻塞](https://www.jianshu.com/p/aed6067eeac9)  
- [聊聊Linux 五种IO模型](https://www.jianshu.com/p/486b0965c296)  
- [聊聊IO多路复用之select、poll、epoll详解](https://www.jianshu.com/p/dfd940e7fca2)  

### 写在最后
文章到这就写完了，下一篇文章的主题应该是Android Q上`Zygote`如何接收其他服务进程的请求，如ATMS，AMS等来创建新的进程，在Zygote这块在Android Q上改动还是比较大的，引入了`AppZygote`(为app加载做一些优化)，`WebViewZygote`和普通的`Zygote`，还有引入了这个`UsapPool`连接池，笔者对于`UsapPool`连接池具体作用还是不太清楚，如果有大神可以在评论指引一下，如果文章有错误的地方也可在评论中指出，感谢万分。  


文章代码存放[链接](https://github.com/ContentPane/Android-Q-Zygote)



### 参考文章
- [Java 世界的盘古和女娲 —— Zygote](https://juejin.im/post/5d8f73bf51882555b149dc64#heading-0) --秉心说大神
- [Android进程系列第二篇---Zygote进程的启动流程](https://www.jianshu.com/p/ab9b83a77af6)
- [Android系统启动流程之Zygote进程启动](https://jsonchao.github.io/2019/02/24/Android%E7%B3%BB%E7%BB%9F%E5%90%AF%E5%8A%A8%E6%B5%81%E7%A8%8B%E4%B9%8BZygote%E8%BF%9B%E7%A8%8B%E5%90%AF%E5%8A%A8/)
- [Android Zygote分析](https://www.jianshu.com/p/7661c068eeb9)
