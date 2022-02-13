@echo off
@rem "to specify default python version to 3.9 create/edit ~/AppData/Local/py.ini with [default] set
@rem to python3=3.9"
set SDKDIR=%~dp0..
py -m pip install pylint -U
py -m pylint --rcfile %SDKDIR%\.pylintrc %SDKDIR%\esv_reference_server %SDKDIR%\server.py %SDKDIR%\contrib %SDKDIR%\unittests
