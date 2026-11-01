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

### 环境要求

内核驱动使用自签测试证书签名。只有在开启了**测试模式（test-signing）**的设备上，驱动防护才能启动，否则 Windows 会拒绝加载驱动。

可以在应用内打开 **设置 → 驱动防护 → 环境检测**：该页面会逐项列出运行条件，说明缺少哪一项、能否自动修复，并可以直接开启测试模式（需要重启 Windows 生效）。

详细步骤见 [文档](https://docs.xiguastudio.top/zh-HANS/Xdows-Security-5/get-started.html)。

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

      使用 Visual Studio/MSBuild 直接生成 `Xdows-Security.slnx` 解决方案即可。该解决方案会同时生成驱动和原生模型项目，并将驱动包复制到主程序输出目录；启用驱动防护时，主程序会按需创建 `Root\XdowsSecurityDriver` 设备、自动安装驱动包并启动驱动。

      或使用发布功能以使用 AOT

### 版权说明

该项目签署了 MIT 授权许可，详情请参阅 [LICENSE](LICENSE.txt)
