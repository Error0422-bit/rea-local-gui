# rea-local-gui
Local GUI reverse engineering tool without MCP
# REA Local GUI

**无需 MCP 的 Windows 本地反编译与静态分析工具**

REA Local GUI 是一个基于 Python Tkinter 的图形化静态分析工具，整合 Ghidra、LIEF、ILSpy、Tree-sitter 和 REA CLI 等工具，帮助用户在本地分析 EXE、DLL、JavaScript 项目及其他受支持的文件。

项目主要面向无法使用 MCP，或希望直接通过 Windows 图形界面进行逆向分析的用户。

**项目状态：v0.1.0 Beta**

## 主要功能

- **快速分析**：自动识别文件类型，选择合适的分析引擎，生成结构化报告。
- **深度反编译**：对单个原生 Windows EXE/DLL，尽可能导出 Ghidra 识别的内部函数及 C 风格伪代码。
- **函数调用关系**：提取静态函数调用信息。
- **.NET 反编译**：借助 ILSpy CLI 恢复受支持的 C# 程序代码。
- **JavaScript 分析**：借助 Tree-sitter 和 REA CLI 分析源码及项目结构。
- **伪代码导出**：将 `functions.jsonl` 转换成方便阅读的 `.c` 风格文本。
- **AI 分析报告**：生成 Markdown 与 JSON 格式的分析结果，便于进一步交给 AI 研究。

本项目不要求 ChatGPT MCP 连接，但部分分析引擎需要单独安装。

## 系统要求

推荐使用 Windows 10/11 64 位系统。

根据需要安装以下组件：

| 组件 | 用途 |
|---|---|
| Python 3.11 | 运行 GUI 和分析调度程序 |
| Ghidra | 原生二进制反编译 |
| Java JDK | 运行 Ghidra |
| LIEF | 解析可执行文件结构 |
| Tree-sitter language pack | 源码结构分析 |
| .NET SDK / ILSpy CLI | .NET 程序反编译 |
| Node.js / npm | 运行 REA CLI |

不需要安装全部组件才能使用基础分析；缺少某个引擎时，对应功能可能不可用。

## 安装教程

### 1. 下载项目

在本 GitHub 仓库点击 **Code → Download ZIP**，下载后解压到自己选择的目录。

不要只下载其中一个 Python 文件，因为 GUI 依赖其他项目文件及 `scripts` 文件夹。

### 2. 安装 Python 依赖

安装 Python 3.11 后，打开 PowerShell，进入项目目录，执行：

`py -3 -m pip install lief tree-sitter-language-pack`

可以通过以下命令检查 Python：

`py -3 --version`

### 3. 安装 Ghidra

从 Ghidra 官方项目获取发行版：

https://github.com/NationalSecurityAgency/ghidra

按照对应 Ghidra 版本的要求安装 Java JDK，并将 Ghidra 解压到本机目录。

在项目根目录新建 `config.json`，内容示例：

`{"ghidra_home": "C:\\Tools\\ghidra_12.1.4_PUBLIC"}`

将路径修改为自己电脑上真实的 Ghidra 安装目录。

也可以通过 `GHIDRA_HOME` 环境变量配置。

### 4. 安装其他可选分析引擎

需要分析 .NET 程序时，先安装 .NET SDK，然后执行：

`dotnet tool install --global ilspycmd`

需要 JavaScript 项目分析时，安装 Node.js。程序将通过 `npx` 调用 `rea-agents`，首次使用可能需要联网下载安装。

REA CLI 的实际可用性取决于对应版本及运行环境。检测到 Node.js 并不意味着 REA 分析已经通过实测。

### 5. 检查环境

在项目目录执行：

`py -3 analysis_core.py --check`

程序会显示 Basic、LIEF、Tree-sitter、Ghidra、ILSpy 和 REA 的检测状态。

注意：引擎显示 `true` 只代表检测到相关环境，不代表已经成功分析过所有格式的文件。

## 启动 GUI

在项目目录双击：

**启动_REA_GUI.bat**

如果无法启动，可以在 PowerShell 中执行：

`py -3 rea_gui.py`

## 使用教程

### 快速分析

1. 点击「添加文件」或「添加文件夹」。
2. 选择「快速分析」。
3. 点击「开始自动分析」。
4. 等待分析完成，在 `reports` 文件夹查看报告。

### 尽可能完整反编译

1. 点击「添加文件」。
2. 选择单个原生 Windows `.exe` 或 `.dll` 文件。
3. 选择「尽可能完整反编译」。
4. 点击「开始自动分析」。
5. 等待 Ghidra 完成分析。

当前深度模式**不支持将整个安装文件夹作为单个任务进行完整反编译**。对于 .NET 程序，深度模式会转入现有的 ILSpy 分析流程。

### 导出 C 风格伪代码

深度分析完成后，点击「导出伪代码 (.c)」，选择报告目录中的 `functions.jsonl`，再选择保存位置。

也可以在命令行执行：

`py -3 export_pseudocode.py "报告目录\functions.jsonl"`

## 报告文件说明

报告通常位于项目的 `reports` 文件夹。

| 文件 | 内容 |
|---|---|
| `summary.md` | 分析摘要 |
| `analysis.json` | 运行状态和元数据 |
| `functions.jsonl` | 深度反编译的函数及伪代码 |
| `calls.jsonl` | 静态函数调用关系 |
| `full_stats.json` | 函数数量、失败和截断统计 |
| `ghidra_full.log` | Ghidra 分析日志 |

不同文件类型和分析模式产生的文件可能不同。

## 已验证的测试

在开发者的 Windows 环境中，使用 Ghidra 对系统程序 `whoami.exe` 进行了实际测试，成功导出了 221 个函数的伪代码和 843 条静态调用关系。

另外，对 WPS 的 `ksolaunch.exe` 进行了单文件深度分析，生成了 2,350 份函数伪代码和 5,393 条静态调用关系；其中一份伪代码达到长度限制，因此该次报告标记为 `partial`。

以上结果仅代表对应测试文件和测试环境，不保证其他软件得到相同结果。

## 已知限制

- 反编译得到的是近似伪代码，不是原始 C/C++ 工程。
- 编译优化、加壳、混淆和动态调用可能影响分析结果。
- 大型二进制文件可能占用较长时间及较多系统资源。
- 深度模式存在执行时间和输出大小限制。
- 当前尚未完成其他 Windows 电脑上的全新安装兼容性测试。
- 本项目不包含 Ghidra、ILSpy、商业软件二进制或任何第三方应用的反编译代码。

## 使用声明

请只分析自己拥有、获得授权或依法允许研究的软件。使用者应遵守适用法律及软件许可协议。

本项目仅提供分析工具，不保证反编译结果的准确性、完整性或可编译性。

## 开源许可

项目许可证待确认。正式添加 `LICENSE` 文件后，以其中内容为准。

欢迎反馈安装问题、提交 Issue 和贡献改进。
