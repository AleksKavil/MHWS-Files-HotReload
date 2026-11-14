# file_hotreload

English | [简体中文](README.zh-CN.md)

## Overview

A live hot-reload plugin for Monster Hunter Wilds resource files (REFramework C++ plugin). Edit and save resource files in the `natives` loose folder and the changes take effect in the running game, without restarting the game or re-entering the scene.

### Supported files

| Type | Effect after saving |
|---|---|
| pfb | Parameters changed in the file are written live into instances already in the scene; instances created later use the new file |
| user | Fields changed in the file are written into the data the game is using |
| efx / uvs / efcsv / htex | Reloaded and references replaced; effects currently playing restart with the new resource. Saving their dependencies (tex, mdf2, mesh, mmtr, uvar, mot, abcmesh, rtex, etc.) reloads the effects that use them |
| mesh / mdf2 / tex / mmtr / rtex | Meshes and materials using them in the scene are replaced immediately, keeping material parameters set at runtime |
| gui | File changes are written into the GUI being displayed (including elements copied at runtime, and added/removed elements) |
| rcol | Collision user data, shape geometry, bound joints, collision layers and masks take effect live |
| chain2 / clsp / gpuc / sfur / jcns / fbxskel / motbank / motlist / mot | Scene components switch to the new resource; when only key values of a mot change, motions currently playing take effect immediately |

Other types are only logged when saved and are not handled.

## Installation

1. Install [REFramework](https://github.com/praydog/REFramework).
2. Put `file_hotreload.dll` into `MonsterHunterWilds\reframework\plugins\`.
3. Start the game.

The plugin sets LooseTextureLoader's `DisableTextureCache` in `reframework\re2_fw_config.txt` to false (takes effect from the next launch) so that loose textures can be reloaded.

## Logs and bug reports

- Messages are written to the REFramework log `re2_framework_log.txt` (prefix `[file_hotreload]`).
- `reframework\data\file_hotreload_crash.log` is created only when the plugin records an exception.
- When reporting a crash, please attach `re2_framework_log.txt`, `file_hotreload_crash.log` (if present) and `reframework_crash.dmp` (if present), and say which file you saved at the time.

## Notes

- At startup the plugin verifies the engine structures it relies on; if a check fails, the related features are disabled automatically (lines starting with `Layout check:` in the log). If something goes wrong after a game update, check these lines first.
- Only problems caused by hot reloading itself are handled; a crash caused by an invalid parameter value happens just the same after restarting the game.
- Some parameters are only used when an object is created; after changing them, the object has to be created again to see the effect.

## Tested environment

- Monster Hunter Wilds 1.42.0.3
- REFramework nightly, commit `1813bf3` (2026-11-01)

## Building

Requires Visual Studio 2022 (or Build Tools) with the C++ desktop development workload (CMake and Ninja included).

```bat
build.bat
```

The output is `build\file_hotreload.dll`. No network access is needed: the REFramework plugin API headers `reframework/API.h` and `API.hpp` are bundled unmodified in `include/reframework`.

- The headers come from [praydog/REFramework](https://github.com/praydog/REFramework) commit `f00d6be` (2026-11-04), plugin API version 1.15.0. This is the version used during development, not a required one.
- The REFramework in the tested environment (commit `1813bf3`) has identical `API.h` and `API.hpp`.
- The loader declares a minimum plugin API version of 1.0.0 (only major version 1 is required), but it has only been tested with the versions above.

A build made with `build.bat -DFILE_HOTRELOAD_VERBOSE=ON` additionally writes the old/new resources of every reload, per-field pfb differences and reference rewrite details to the REFramework log.

## License

[MIT](LICENSE).

The REFramework plugin API headers in `include/reframework` belong to [REFramework](https://github.com/praydog/REFramework) and are included under its license, see [include/reframework/LICENSE](include/reframework/LICENSE).
