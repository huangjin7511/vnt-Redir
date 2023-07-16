# switch
 A virtual network tool (VPN)

将不同网络下的多个设备虚拟到一个局域网下


### 快速使用：

1. 指定一个token，在多台设备上运行该程序，例如：
    ```shell
      # linux上
      root@DESKTOP-0BCHNIO:/opt# ./switch-cmd start --token 123456
      # 在另一台linux上使用nohup后台运行
      root@izj6cemne76ykdzkataftfz switch# nohup ./switch-cmd start --token 123456 &
      # windows上
      D:\switch\bin_v1>switch-cmd.exe start --token 123456
    ```
2. 可以执行info命令查看当前设备的虚拟ip
   ```shell
    root@DESKTOP-0BCHNIO:/opt# ./switch-cmd --info
    Name: Ubuntu 18.04 (bionic) [64-bit]
    Virtual ip: 10.26.0.2
    Virtual gateway: 10.26.0.1
    Virtual netmask: 255.255.255.0
    Connection status: Connected
    NAT type: Cone
    Relay server: 43.139.56.10:29871
    Public ips: 120.228.76.75
    Local ip: 172.25.165.58
    ```
3. 也可以执行list命令查看其他设备的虚拟ip
   ```shell
    root@DESKTOP-0BCHNIO:/opt# ./switch-cmd --list
    Name                                                       Virtual Ip      P2P/Relay      Rt      Status
    Windows 10.0.22621 (Windows 11 Professional) [64-bit]      10.26.0.3       p2p            2       Online
    CentOS 7.9.2009 (Core) [64-bit]                            10.26.0.4       p2p            35      Online
    ```
4. 最后可以用虚拟ip实现设备间相互访问
   1. ping

      <img width="506" alt="ping" src="https://raw.githubusercontent.com/lbl8603/switch/dev/documents/img/ping.jpg">
   2. ssh
   
      <img width="506" alt="ssh" src="https://raw.githubusercontent.com/lbl8603/switch/dev/documents/img/ssh.jpg">
5. 帮助，使用-h命令查看

### 更多玩法

1. 和远程桌面(如mstsc)搭配，超低延迟的体验
2. 安装samba服务，共享磁盘
3. 搭配公网服务器nginx反向代理，在公网访问本地文件
4. 点对网(结合启动参数'--in-ip'和'--out-ip')


### 使用须知
- token的作用是标识一个虚拟局域网，当使用公共服务器时，建议使用一个唯一值当token(比如uuid)，否则有可能连接到其他人创建的虚拟局域网中
- 建议指定deviceId，默认使用MAC地址，在某些环境下可能发生变化，**注意不要重复**
- 公共服务器目前的配置是2核4G 4Mbps，有需要再扩展~
- 需要root/管理员权限
- 使用命令行运行
- Mac和Linux下需要加可执行权限(例如:chmod +x ./switch-macos)
- 自己搭注册和中继服务器(https://github.com/lbl8603/switch-server)
### 编译
 前提条件:安装rust编译环境(https://www.rust-lang.org/zh-CN/tools/install)
 
 到项目根目录下执行 cargo build -p switch-cmd
 
### 支持平台
- Mac
- Linux
- Windows
  - 使用tun网卡 依赖wintun.dll(https://www.wintun.net/ )(将dll放到同目录下，建议使用版本0.14.1)
  - 使用tap网卡 依赖tap-windows(https://build.openvpn.net/downloads/releases/ )(建议使用版本9.24.7)

### 特性
- IP层数据转发
  - tun虚拟网卡
  - tap虚拟网卡
- NAT穿透
  - 点对点穿透
  - 服务端中继转发
  - 客户端中继转发
- IP代理
- p2p组播/广播
- 客户端数据加密

### Todo
- 支持安卓
- 服务端数据加密

### 常见问题
#### 问题1: 设置网络地址失败
##### 可能原因:
switch默认使用10.26.0.0/24网段，和本地网络适配器的ip冲突
##### 解决方法:
1. 方法一：找到冲突的IP，将其改成别的
2. 方法二：自建服务器，指定其他不会冲突的网段
3. 方法三：增加参数--device-id，设置不同的id会让switch-server分配不同的IP，从而绕开有冲突的IP
