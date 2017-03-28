# brew install mingw-w64

GOOS='windows' \
CC='/usr/local/opt/mingw-w64/bin/x86_64-w64-mingw32-gcc' \
CXX='/usr/local/opt/mingw-w64/bin/x86_64-w64-mingw32-g++' \
CGO_ENABLED='1' \
go build