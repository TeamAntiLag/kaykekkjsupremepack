��&cls
ÿþ&cls
@echo off
color 03
title by kaykekkj
cls
@echo by kayke kkj
@echo.
@echo Quer Desistalar Microsoft Edge?
@echo.
pause

cd C:\Program Files (x86)\Microsoft\Edge\Application\8*\Installer
@echo.
setup.exe --uninstall --system-level --verbose-logging --force-uninstall

DISM /online /disable-feature /featurename:Internet-Explorer-Optional-amd64
@echo.
@echo Microsoft Edge Desistalado com Sucesso!
@echo.
pause