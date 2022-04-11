@echo off
@rem "to specify default python version to 3.9 create/edit ~/AppData/Local/py.ini with [default] set
@rem to python3=3.9"
set SDKDIR=%~dp0..
py -m pip install pylint==2.12.2
py -m pylint --rcfile %SDKDIR%\.pylintrc %SDKDIR%\simple_indexer %SDKDIR%\server.py %SDKDIR%\contrib %SDKDIR%\unittests
