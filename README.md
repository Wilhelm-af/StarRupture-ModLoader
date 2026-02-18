# StarRupture ModLoader

A DLL mod for [Star Rupture](https://store.steampowered.com/app/1187810/Star_Rupture/) that simplifyes dll loading as a ModLoader

## Installation

1. Download the latest release zip from the [Releases](../../releases) page.
2. Extract it into your game directory (the folder containing `StarRupture-Win64-Shipping.exe`), so that `dwmapi.dll` sits next to the game executable
3. Create a Mods folder where the DLL mods can go.


```
StarRupture/
  StarRupture-Win64-Shipping.exe
  dwmapi.dll                        <-- proxy loader
  Mods/
    ExampleModFolder/
      Modfiles.dll               <-- the mod
      mod.json                  <-- the config to tell wich file is the main DLL file.
```

## How it works

**Proxy loader** (`dwmapi.dll`): Placed next to the game executable, Windows loads it in place of the real `dwmapi.dll` (DLL search order hijacking). It forwards all real dwmapi calls to the system DLL via assembly trampolines, then scans `Mods/` subfolders for `mod.json` manifests and loads each mod DLL.

Example would be the use of UE4SS-RE where you place the UE4SS folder in the `Mods/` folder and make a mod.json with this information

```
{
  "name": "UE4SS",
  "dll": "UE4SS.dll",
  "enabled": true
}
```
This has been tested and works with latest dev release of UE4SS

## Build from source

Requires Linux with MinGW-w64 cross-compiler and CMake 3.20+.

```bash
# Install dependencies (Arch/Manjaro)
sudo pacman -S mingw-w64-gcc cmake

# Build
cmake -B build -DCMAKE_TOOLCHAIN_FILE=cmake/mingw-toolchain.cmake -DCMAKE_BUILD_TYPE=Release
cmake --build build -j$(nproc)
```

Outputs: `build/dwmapi.dll`.

## Contributions

Id like to thank UE4SS for the proxy solution on dwmapi.dll files making this mod loader posible.


## License

All rights reserved under the GNU GENERAL PUBLIC LICENSE v3
Refere to LICENSE
