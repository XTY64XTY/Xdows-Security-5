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

### License

This project is licensed under the MIT License. See [LICENSE](LICENSE.txt) for details.
