# Hook ActivationContext

This is simple tool to hook and force process to load redirected DLL.

To build and test code you will need **Visual Studio Build tools** 2013, 2015 or 2017, either standalone or one integrated with Visual Studio, and **cmake**:

* [Visual C++ 2015 Build tools](http://landinghub.visualstudio.com/visual-cpp-build-tools)
* [Build Tools for Visual Studio 2017](https://www.visualstudio.com/downloads/#build-tools-for-visual-studio-2017)
* [cmake](https://cmake.org/)

Code is manipulating Activation Context DLL redirection in 2 ways. One method would be to fake **AssemblyDirectory** to point to the fake folder where you would store your fake DLL. For this attack **sxsoaps.dll** is used which is at the same time present in the **SystemDefaultActivationContextData**.

Another attack is to add new DLL redirection which will cause call **LoadLibrary("meh.dll")** to load **redirecteddll.dll**, and this attack can be used against the remote process to fake path of a system dll. In this case I chose to attack **advapi32.dll** loading.

Of course, next steps would be COM redirection for example, or window class hijacking, but that can be left as an exercise.

Code also gives ability to debug child process with **--debug** flag.

```
actctx.exe --debug
```

This will cause process to run in infinite loop at the **LdrInitializeThunk** thus debugger can be attached and ActivationContext data parsing can be debugged if needed.

Similar code for LdrDebug break you may find at [ReWolf's](https://twitter.com/rwfpl) code [repository](https://github.com/rwfpl/rewolf-ldrdebug) if you intend to do stand alone debugging from the very start of the process.
