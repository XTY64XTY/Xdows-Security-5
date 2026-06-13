<p align="center">
  <a href="https://github.com/XTY64XTY/Xdows-Security-5">
    <img src=".\Xdows-Security\logo.ico" alt="Logo" width="80" height="80">
  </a>

  <h3 align="center">Xdows Security 5</h3>
  <p align="center">
    來看看下一代基於 WinUI3 + C# 技術構建的殺毒軟件
    <br />
    <a href="https://docs.xiguastudio.top/zh-HANT/Xdows-Security-5/get-started.html">文檔</a>
    ·
    <a href="https://github.com/XTY64XTY/Xdows-Security-5/issues">反饋</a>
    ·
    <a href="https://github.com/XTY64XTY/Xdows-Security-5/releases">下載</a>
    <br />
    <a href="README.md">English</a>
    ·
    <a href="README.zh-HANS.md">简体中文</a>
    ·
    繁體中文
  </p>

</p>

### 使用方式

#### 直接使用

1. 打開 [Releases](https://github.com/XTY64XTY/Xdows-Security-5/releases) 下載最新版本的 `Xdows-Security.zip`
2. 解壓壓縮包到目標位置，運行 `Xdows-Security.exe`

#### 編譯運行

1. 環境要求：
    - 操作系統：Windows 10/11
    - 軟件環境：Git、Visual Studio 2026
    - 網絡環境：正常訪問 GitHub
    - 工作負載：請打開解決方案查看

2. 編譯運行:

    1. 克隆同級倉庫

      ```sh
      git clone https://github.com/XTY64XTY/Xdows-Security-5
      git clone https://github.com/XTY64XTY/Xdows-Model
      git clone https://github.com/XTY64XTY/Xdows-Security-Driver
      ```

    2. 生成項目

      使用 Visual Studio/MSBuild 直接生成 `Xdows-Security.slnx` 解決方案即可。該解決方案會同時生成驅動和原生模型項目，並將驅動包複製到主程序輸出目錄；啟用驅動防護時，主程序會按需建立 `Root\XdowsSecurityDriver` 裝置、自動安裝驅動包並啟動驅動。

      或使用發佈功能以使用 AOT

### 版權說明

該項目簽署了 MIT 授權許可，詳情請參閱 [LICENSE](LICENSE.txt)
