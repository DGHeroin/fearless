build_path="./out"
mkdir -p ${build_path}
GOOS=darwin  GOARCH=amd64 go build -o ${build_path}/fearless-darwin
GOOS=linux   GOARCH=amd64 go build -o ${build_path}/fearless-linux
GOOS=linux   GOARCH=386   go build -o ${build_path}/fearless-linux32
GOOS=linux   GOARCH=arm GOARM=5 go build -o ${build_path}/fearless-arm5-rpi
GOOS=windows GOARCH=amd64 go build -o ${build_path}/fearless-win.exe
GOOS=windows GOARCH=386   go build -o ${build_path}/fearless-win32.exe
