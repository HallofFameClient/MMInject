@echo off
set VSWHERE=C:\Program Files (x86)\Microsoft Visual Studio\Installer\vswhere.exe
if exist "%VSWHERE%" (
  for /f "usebackq tokens=*" %%i in (`"%VSWHERE%" -prerelease -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do set VSINST=%%i
)
if not defined VSINST set VSINST=C:\Program Files\Microsoft Visual Studio\18\Insiders
call "%VSINST%\VC\Auxiliary\Build\vcvars64.bat" >nul
dotnet publish -c Release -r win-x64 -p:IlcUseEnvironmentalTools=true
