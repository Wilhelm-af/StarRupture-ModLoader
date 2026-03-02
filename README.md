# Collaboration :D

So we were two idiots starting at this at the same time, Comming up with idea and such to how to solve problems.
After some time now https://github.com/AlienXAXS has made a more "Stable" thought thru modloader that works for both Client And Server.
So with that, im deprecating this project and will help AlienXAXS with his projects to have a more uniformed solution to the users out there.

Makeing it simple for people to select one modloader for everything instead of having to choose between one and another and or using both.
Here is the link to the [ModLoader](https://github.com/AlienXAXS/StarRupture-ModLoader) and ill see you there.


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
