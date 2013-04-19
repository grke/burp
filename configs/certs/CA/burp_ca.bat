echo off

REM This script is based on burp_ca, runs on Windows, and contains only the
REM stuff that the client needs to run.
REM
REM It is going to be run with arguments that look like the following:
REM burp_ca.bat --key --keypath "C:/Program Files/Burp/ssl_cert-client.key" --request --requestpath "C:/Program Files/Burp/CA/win2008.csr" --name win2008

REM The tildas here stop Windows putting quotes around the variable.
set "keypath=%~3"
set "requestpath=%~6"
set "name=%~8"
REM Need to set OPENSSL_CONF otherwise openssl tries to find an conf file from
REM within my mingw build environment. Set it to an empty file that the
REM installer will create.
REM Burp used to always put things in C:\Program Files\Burp\, but as of
REM 1.3.11, it changed to putting them in %PROGRAMFILES%, but still want to
REM let the old way work.
IF EXIST "C:\Program Files\Burp" (
	set "OPENSSL_CONF=C:\Program Files\Burp\openssl.conf"
	set "openssl=C:\Program Files\Burp\bin\openssl.exe"
	set "tmpconf=C:\Program Files\Burp\CA\tmp.conf"
) ELSE (
	set "OPENSSL_CONF=%PROGRAMFILES%\Burp\openssl.conf"
	set "openssl=%PROGRAMFILES%\Burp\bin\openssl.exe"
	set "tmpconf=%PROGRAMFILES%\Burp\CA\tmp.conf"
)

if %3.==. goto notenoughparams
if %6.==. goto notenoughparams
if %8.==. goto notenoughparams

REM Need to change forward slashes to backslashes in the paths.
set keypath=%keypath:/=\%
set requestpath=%requestpath:/=\%

echo "generating key %name%: %keypath%"
"%openssl%" genrsa -out "%keypath%" 2048

REM Need to create a config file for openssl in order to make a certicate
REM signing request. There must be a neater way to do it than one line at a time
REM and %tmpconf% at the end each time.
echo RANDFILE = /dev/urandom > "%tmpconf%"
echo [ req ] >> "%tmpconf%"
echo distinguished_name = req_distinguished_name >> "%tmpconf%"
echo prompt = no >> "%tmpconf%"
echo [ v3_req ] >> "%tmpconf%"
echo basicConstraints=CA:false >> "%tmpconf%"
echo [ req_distinguished_name ] >> "%tmpconf%"
echo commonName = %name% >> "%tmpconf%"

echo "generating certificate signing request: %requestpath%"
"%openssl%" req -config "%tmpconf%" -new -key "%keypath%" -out "%requestpath%" -extensions v3_req
del "%tmpconf%"
exit 0

:notenoughparams
echo "burp_ca.bat not given enough parameters"
exit 1

