@echo off

rem Deletes recursively the directory specified by the `--dir` command line
rem argument of the script. The directory must be an updater install path.

echo %1 %2 %3 %4
if not "%1"=="--dir" (
  echo "Invalid switch."
  exit 1
)

set Directory=%2
set RemoveDirectory=%4

rem Validate the path is an updater path.
@echo %Directory% | FindStr /L \OneStart.ai\OneStartUpdater > nul
if %ERRORLEVEL% NEQ 0 (
  echo "Invalid argument."
  exit 2
)

rem Try deleting the directory 15 times and wait one second between tries.
for /L %%G IN (1,1,15) do (
  ping -n 2 127.0.0.1 > nul
  rmdir %Directory% /s /q > nul
  if not exist %Directory% (
    if "%3"=="--remove-dir" (
      rmdir %RemoveDirectory% /s /q > nul
      if not exist %RemoveDirectory% exit 0 
    ) else (
      exit 0
    )
  )
)

exit 3

