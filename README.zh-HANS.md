<p align="center">
  <a href="https://github.com/XTY64XTY/Xdows-Security-5">
    <img src=".\Xdows-Security\logo.ico" alt="Logo" width="80" height="80">
  </a>

  <h3 align="center">Xdows Security 5</h3>
  <p align="center">
    来看看下一代基于 WinUI3 + C# 技术构建的杀毒软件
    <br />
    <a href="https://docs.xiguastudio.top/zh-HANS/Xdows-Security-5/get-started.html">文档</a>
    ·
    <a href="https://github.com/XTY64XTY/Xdows-Security-5/issues">反馈</a>
    ·
    <a href="https://github.com/XTY64XTY/Xdows-Security-5/releases">下载</a>
    <br />
    <a href="README.md">English</a>
    ·
    简体中文
    ·
    <a href="README.zh-HANT.md">繁體中文</a>
  </p>

</p>

### 使用方式

#### 直接使用

1. 打开 [Releases](https://github.com/XTY64XTY/Xdows-Security-5/releases) 下载最新版本的 `Xdows-Security.zip`
2. 解压压缩包到目标位置，运行 `Xdows-Security.exe`

#### 编译运行

1. 环境要求：
    - 操作系统：Windows 10/11
    - 软件环境：Git、Visual Studio 2026
    - 网络环境：正常访问 GitHub
    - 工作负载：请打开解决方案查看

2. 编译运行:

    1. 克隆同级仓库

      ```sh
      git clone https://github.com/XTY64XTY/Xdows-Security-5
      git clone https://github.com/XTY64XTY/Xdows-Model
      git clone https://github.com/XTY64XTY/Xdows-Security-Driver
      ```

    2. 生成项目

      使用 Visual Studio/MSBuild 直接生成 `Xdows-Security.slnx` 解决方案即可。该解决方案会同时生成驱动和原生模型项目，并将驱动包复制到主程序输出目录；启用驱动防护时，主程序会按需创建或复用 `Root\XdowsSecurityDriver` 根设备，使用 `pnputil` 暂存 `Driver\Xdows-Security-Driver.inf`，再将驱动包绑定到根设备、启动 `Xdows-Security-Driver` 服务并检查桥接通信。

      或使用发布功能以使用 AOT

### 版权说明

该项目签署了 MIT 授权许可，详情请参阅 [LICENSE](LICENSE.txt)
