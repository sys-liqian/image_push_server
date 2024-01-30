# Image Push Server

http server is used to upload docker image tar, parse the tar and upload it to the registry.

## Build

```bash
go build -o bin/image-push-server main.go
```

## Usage

### Start Registry

```bash
docker run --name tst-registry -d -p 5000:5000 registry:2
```

### Upload Image Tar

```bash
docker save alpine:3.18 -o alpine-3.18.tar

curl -v -X POST http://localhost:8080/upload -F "file=@./alpine-3.18.tar" -F "address=http://localhost:5000"
```

### Form data Parameter

* address: registry or harbor server address,`required`
* file: docker iamge tar file path,`required`
* username: registry or harbor username.
* password: reegistry or harbor password.
* shipTls: skip ssl verify.
* chunkSize: default Monolithic Upload, if chunkSie is set,use Chunked Upload.