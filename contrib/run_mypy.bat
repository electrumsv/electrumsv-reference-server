@echo off
@rem "to specify default python version to 3.9 create/edit ~/AppData/Local/py.ini with [default] set
@rem to python3=3.9"

REM Get current folder with no trailing slash
SET ScriptDir=%~dp0
SET SdkDir=%ScriptDir%\..
echo %ScriptDir%
cd %ScriptDir%
mypy --install-types --non-interactive
mypy --config=%SdkDir%\mypy.ini %SdkDir%\esv_reference_server  --python-version 3.10

