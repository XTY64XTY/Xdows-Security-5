<p align="center">
  <a href="https://github.com/XTY64XTY/Xdows-Security-5">
    <img src=".\Xdows-Security\logo.ico" alt="Logo" width="80" height="80">
  </a>

  <h3 align="center">Xdows Security 5</h3>
  <p align="center">
    Check out the next-generation antivirus software built with WinUI3 + C#
    <br />
    <a href="https://docs.xiguastudio.top/en-US/Xdows-Security-5/get-started.html   ">Documentation</a>
    ·
    <a href="https://github.com/XTY64XTY/Xdows-Security-5/issues">Feedback</a>
    ·
    <a href="https://github.com/XTY64XTY/Xdows-Security-5/releases">Download</a>
    <br />
    English
    ·
    <a href="README.zh-HANS.md">简体中文</a>
    ·
    <a href="README.zh-HANT.md">繁體中文</a>
  </p>

</p>

### Usage

#### Direct Use

1. Open [Releases](https://github.com/XTY64XTY/Xdows-Security-5/releases   ) to download the latest version of `Xdows-Security.zip`
2. Extract the archive to your desired location and run `Xdows-Security.exe`

#### Build and Run

1. Requirements:
    - Operating System: Windows 10/11
    - Software: Git, Visual Studio 2026
    - Network: Normal access to GitHub
    - Workloads: Please open the solution to check

2. Build and Run:

    1. Clone the sibling repositories

      ```sh
      git clone https://github.com/XTY64XTY/Xdows-Security-5   
      git clone https://github.com/XTY64XTY/Xdows-Model
      git clone https://github.com/XTY64XTY/Xdows-Security-Driver
      ```

    2. Build the project

      Build the `Xdows-Security.slnx` solution with Visual Studio/MSBuild. The solution references `Xdows-Model-Native` and `Xdows-Security-Driver`, so the app output contains the native model runtime and driver package after one solution build.

      Or use the Publish feature to enable AOT compilation

#### Driver Protection Development

The driver-backed protection path spans three sibling repositories under `D:\Code`:

- `Xdows-Security`: WinUI app, protection bridge, environment repair UI, logging, and user decisions.
- `Xdows-Security-Driver`: KMDF driver, shared protocol, VS/WDK-generated driver package, and VM validation matrix.
- `Xdows-Model`: ONNX models and `Xdows-Model-Native.dll`.

Build local development output from the main solution:

```powershell
& 'D:\Visual-Studio\MSBuild\Current\Bin\amd64\MSBuild.exe' `
  'D:\Code\Xdows-Security\Xdows-Security.slnx' `
  /p:Configuration=Debug `
  /p:Platform=x64 `
  /p:WindowsTargetPlatformVersion=10.0.28000.0 `
  /p:SignMode=Off `
  /m
```

The app output should contain:

- `Xdows-Model.onnx`, `Xdows-Model-Flash.onnx`, `Xdows-Model-Pro.onnx`
- `Xdows-Model-Native.dll`
- `onnxruntime.dll`, `onnxruntime_providers_shared.dll`
- `Driver\Xdows-Security-Driver.inf`
- `Driver\Xdows-Security-Driver.sys`
- `Driver\xdows-security-driver.cat`

Local verification:

```powershell
& 'D:\Code\Xdows-Security\tests\Invoke-DriverBridgeProtocolSmoke.ps1'
& 'D:\Code\Xdows-Security\tests\Invoke-PublishAssetSmoke.ps1'
```

Driver install, repair, and unload require an elevated test machine. When Driver Protection is enabled, Xdows Security now performs the full service registration path itself: it stops any stale service, creates or reuses the `Root\XdowsSecurityDriver` root device, stages the `Driver\Xdows-Security-Driver.inf` package with `pnputil`, binds that package to the root device, starts `Xdows-Security-Driver`, then checks whether the bridge is reachable. Enable Windows test-signing on the VM if the development driver signature is not trusted.

### License

This project is licensed under the MIT License. See [LICENSE](LICENSE.txt) for details.
