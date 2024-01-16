@echo off
set myapp=httpproxy.exe
rem taskkill /f /im %myapp%

:mainloop
    set dt=%date:~4,2%.%date:~7,2%
    set tm=%time:~0,8%
    set tm=%tm: =0%
    tasklist /fi "ImageName eq %myapp%" /fo csv 2>NUL | find /I "%myapp%">NUL
    if "%ERRORLEVEL%"=="0" (
        rem echo %tm% check ok
    ) else (
        echo %dt% %tm% started
        rem keep session or not = /k or /c
        rem start "http-proxy %dt% %tm%" cmd /k httpproxy.exe
        shutdown /t 999999>nul
        rem if there is already a shutdown pending then %ERRORLEVEL% will be 1190
        if %ERRORLEVEL% equ 1190 (
            echo A shutdown is pending
            exit /b
        ) else (
            rem cancel the "test" shutdown
            shutdown /a 2>nul
            rem echo No shutdown is pending
        )
        start "http-proxy %dt% %tm%" cmd /c httpproxy.exe
    )
    timeout /t 3 >NUL
goto :mainloop