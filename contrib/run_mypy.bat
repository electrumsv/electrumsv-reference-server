@echo off
@rem "to specify default python version to 3.9 create/edit ~/AppData/Local/py.ini with [default] set
@rem to python3=3.9"

REM Get current folder with no trailing slash
SET ScriptDir=%~dp0
SET SdkDir=%ScriptDir%\..
pushd %SdkDir%
py -3.10 -m mypy --config-file mypy.ini --install-types --non-interactive --python-version 3.10
popd

