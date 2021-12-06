@echo off
@rem "to specify default python version to 3.9 create/edit ~/AppData/Local/py.ini with [default] set
@rem to python3=3.9"
set SDKDIR=%~dp0..\esv_reference_server
py -m pip install pylint -U
py -m pylint --rcfile ../.pylintrc %SDKDIR%
