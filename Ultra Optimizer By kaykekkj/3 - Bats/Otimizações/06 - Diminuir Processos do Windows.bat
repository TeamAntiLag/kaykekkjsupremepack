��&cls
ÿþ&cls
@echo off
color 03
title by kaykekkj
:menu
ECHO.
ECHO    - Selecione Abaixo o Valor da sua Memoria Ram -
ECHO. 
ECHO.
ECHO       1 - 4GB
ECHO       2 - 6GB
ECHO       3 - 8GB
ECHO       4 - 12GB
ECHO       5 - 16GB
ECHO       6 - Sair
ECHO.
SET /P M=Digite o Valor da Sua Ram e Pressione Enter:
cls
IF %M%==1 GOTO 4GB
cls
IF %M%==2 GOTO 6GB
cls
IF %M%==3 GOTO 8GB
cls
IF %M%==4 GOTO 12GB
cls
IF %M%==5 GOTO 16GB
cls
IF %M%==6 GOTO EOF
cls
:4GB
reg add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Control" /v "SvcHostSplitThresholdInKB" /t REG_DWORD /d "68764420" /f
GOTO MENU
cls
:6GB
reg add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Control" /v "SvcHostSplitThresholdInKB" /t REG_DWORD /d "103355478" /f
GOTO MENU
cls
:8GB
reg add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Control" /v "SvcHostSplitThresholdInKB" /t REG_DWORD /d "137922056" /f
GOTO MENU
cls
:12GB
reg add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Control" /v "SvcHostSplitThresholdInKB" /t REG_DWORD /d "307767570" /f
GOTO MENU
cls
:16GB
reg add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Control" /v "SvcHostSplitThresholdInKB" /t REG_DWORD /d "376926742" /f
GOTO MENU
cls