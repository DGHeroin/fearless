# fearless
一个科学工具.

inspired by 15d6ae31367740e7fde579c186351d0665da07de

### 用法
服务端客户端共享一个可执行文件

#### 服务端
```
./fearless -s -port 6668 -http :7788
开启服务在6668端口, 用来提供代理服务
开启http 7778 端口, 用来提供 TLS 秘钥共享服务
```

#### 客户端
```
/fearless -http http://127.0.0.1:7788 -port 2080 -remote 127.0.0.1:6668
```

#### 更多参数说明
```
Usage of ./fearless:
  -auto
    	auto config (default true) 
      自动配置, 如果不是自动配置, 则要自行维护x509的证书.
      对应证书为ca.key/ca.cert/server.key/server.cert/client.key/client.cert
  -ca string
    	ca file path
      非自动配置时, 指定的ca.cert路径
  -cert string
    	cert file path
      非自动配置时, 指定的[client/server].cert路径
  -http string
    	http share address (default ":8089")
      http共享的地址, 当作为服务端时作为监听地址, 当作为客户端时作为连接地址
  -key string
    	key file path
      非自动配置时, 指定的[client/server].key路径
  -port int
    	listen port
      作为服务端时代理的服务端口, 作为客户端时为socks5服务端口
  -remote string
    	remote server address
      作为客户端时, 连接远程的代理端口
  -s	run as fearless server
      是否当做服务端运行
  -token string
    	key share token (default "kungfu")
      http共享秘钥
      
```
