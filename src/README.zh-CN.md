# file_hotreload

[English](README.md) | 简体中文

## 简介

怪物猎人荒野的资源文件实时热重载插件（REFramework C++ 插件）。在 `natives` 松散文件夹中修改并保存资源文件后，游戏运行中立即生效，不用重启游戏或重新进入场景。

### 支持的文件

| 类型 | 保存后的效果 |
|---|---|
| pfb | 文件改了的参数实时写入场景中已有的实例；之后新生成的实例使用新文件 |
| user | 文件改了的字段写入游戏正在使用的数据 |
| efx / uvs / efcsv / htex | 重新加载并替换引用，正在播放的特效以新资源重新播放；其依赖（tex、mdf2、mesh、mmtr、uvar、mot、abcmesh、rtex 等）保存后会级联重载特效 |
| mesh / mdf2 / tex / mmtr / rtex | 场景中使用它们的网格、材质立即换新，保留运行时设置的材质参数 |
| gui | 文件修改写入正在显示的界面（含运行时复制出的元素、增删元素） |
| rcol | 碰撞用户数据、形状几何、绑定骨骼、碰撞层与掩码实时生效 |
| chain2 / clsp / gpuc / sfur / jcns / fbxskel / motbank / motlist / mot | 场景组件换用新资源；mot 只改关键帧数值时正在播放的动作立即生效 |

其余类型保存时只记日志、不做处理。

## 安装

1. 安装 [REFramework](https://github.com/praydog/REFramework)。
2. 把 `file_hotreload.dll` 放进 `MonsterHunterWilds\reframework\plugins\`。
3. 启动游戏。

插件会把 `reframework\re2_fw_config.txt` 中 LooseTextureLoader 的 `DisableTextureCache` 改为 false（下次启动生效），以便松散贴图能被重载。

## 日志与问题反馈

- 运行信息写在 REFramework 日志 `re2_framework_log.txt` 中（带 `[file_hotreload]` 前缀）。
- 只有出现问题时才会生成 `reframework\data\file_hotreload_crash.log`：插件记录到异常，或有功能被停用（启动时结构核对未通过、找不到引擎函数）。记录跨启动保留；文件超过 1 MB 后，下次写入前会改名为 `file_hotreload_crash.prev.log`（覆盖上一个）。
- 反馈崩溃时请附上：`re2_framework_log.txt`、`file_hotreload_crash.log` 与 `file_hotreload_crash.prev.log`（如有）、`reframework_crash.dmp`（如有），并说明当时保存了哪个文件。

## 注意

- 插件启动时会核对用到的引擎结构，不通过时相关功能自动停用，并记录到 `file_hotreload_crash.log`（详细信息见 REFramework 日志中 `Layout check:` 开头的几行）。游戏更新后如有异常，请先查看这个文件。
- 只处理热重载本身造成的问题；参数值本身不合法导致的崩溃，重启游戏后同样会出现。
- 部分参数只在对象生成时使用，修改后需要重新生成对象才能看到效果。

## 测试环境

- Monster Hunter Wilds 1.42.0.3
- REFramework nightly，提交 `1813bf3`（2026-11-01）

## 编译

需要 Visual Studio 2022（或 Build Tools）的 C++ 桌面开发组件（含 CMake、Ninja）。

```bat
build.bat
```

输出 `build\file_hotreload.dll`。编译不需要联网：REFramework 插件 API 头文件 `reframework/API.h`、`API.hpp` 已随源码放在 `include/reframework`，未做修改。

- 头文件取自 [praydog/REFramework](https://github.com/praydog/REFramework) 提交 `f00d6be`（2026-11-04），插件 API 版本 1.15.0。这是开发时使用的版本，不是必须的版本。
- 测试环境中的 REFramework（提交 `1813bf3`）的 `API.h`、`API.hpp` 与这份相同。
- 加载器声明的最低插件 API 版本为 1.0.0（只要求主版本号为 1），但只在上述版本上测试过。

`build.bat -DFILE_HOTRELOAD_VERBOSE=ON` 编译出的版本会在 REFramework 日志中额外输出每次重载的新旧资源、pfb 逐字段差异与引用改写明细。

## 许可证

[MIT](LICENSE)。

`include/reframework` 下的 REFramework 插件 API 头文件属于 [REFramework](https://github.com/praydog/REFramework)，按其许可证随附，见 [include/reframework/LICENSE](include/reframework/LICENSE)。
