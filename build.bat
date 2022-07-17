mkdir release
SET CGO_ENABLED=0
SET GOOS=linux
SET GOARCH=amd64
go build -o release\fearless cmd\fearless\fearless.go