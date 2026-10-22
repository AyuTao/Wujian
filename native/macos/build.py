#!/usr/bin/env python3
"""Build only. Never installs/enables a network filter or changes OS settings."""
import argparse
import datetime
import pathlib
import plistlib
import shutil
import subprocess
import sys

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parent.parent
HOST_ID = "io.wujian.guard.host"
EXT_ID = "io.wujian.guard.packet"
CAPABILITY = "content-filter-provider-systemextension"

def run(args, **kwargs):
    return subprocess.run([str(a) for a in args], check=True, **kwargs)

def capture(args):
    return run(args, capture_output=True, text=True).stdout.strip()

def write_plist(path, value):
    path.write_bytes(plistlib.dumps(value, sort_keys=True))

def read_profile(path, bundle, host):
    raw = run(["/usr/bin/security", "cms", "-D", "-i", path], capture_output=True).stdout
    profile = plistlib.loads(raw)
    ent = profile.get("Entitlements", {})
    team = (profile.get("TeamIdentifier") or [None])[0]
    app = ent.get("com.apple.application-identifier", ent.get("application-identifier", ""))
    expiry = profile.get("ExpirationDate")
    if not team or app != f"{team}.{bundle}" or not expiry or expiry.replace(tzinfo=datetime.timezone.utc) <= datetime.datetime.now(datetime.timezone.utc):
        raise ValueError("描述文件标识、团队或有效期不符合此组件")
    if CAPABILITY not in ent.get("com.apple.developer.networking.networkextension", []):
        raise ValueError("描述文件未授权 Network Extension content-filter-provider-systemextension")
    if host and not ent.get("com.apple.developer.system-extension.install"):
        raise ValueError("宿主描述文件未授权安装系统扩展")
    return team

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mmdb", type=pathlib.Path)
    parser.add_argument("--typecheck-only", action="store_true")
    parser.add_argument("--sign-identity")
    parser.add_argument("--host-profile", type=pathlib.Path)
    parser.add_argument("--extension-profile", type=pathlib.Path)
    args = parser.parse_args()
    if sys.platform != "darwin":
        raise ValueError("macOS 系统扩展只能在 macOS 构建")
    core = HERE / "GuardCore"
    run(["swift", "build", "--package-path", core, "-c", "release"])
    lib = pathlib.Path(capture(["swift", "build", "--package-path", core, "-c", "release", "--show-bin-path"]))
    sdk = capture(["xcrun", "--sdk", "macosx", "--show-sdk-path"])
    arch = capture(["uname", "-m"])
    modules = lib / "Modules" if (lib / "Modules").is_dir() else lib
    flags = ["xcrun", "swiftc", "-swift-version", "5", "-parse-as-library", "-sdk", sdk, "-target", f"{arch}-apple-macos14.0", "-I", modules, "-L", lib, "-lGuardCore"]
    extension_sources = [HERE / "PacketFilterProvider.swift", HERE / "ExtensionMain.swift"]
    host_sources = [HERE / "GuardHost.swift"]
    if args.typecheck_only:
        run(flags + ["-typecheck"] + extension_sources)
        run(flags + ["-typecheck"] + host_sources)
        print("Native provider and host typecheck passed; no installation performed")
        return
    if not args.mmdb:
        raise ValueError("构建需要 --mmdb 指向本地 Country.mmdb；不自动下载第三方数据")
    installable = bool(args.sign_identity and args.host_profile and args.extension_profile)
    if any([args.sign_identity, args.host_profile, args.extension_profile]) and not installable:
        raise ValueError("可安装签名需要同时提供签名身份、宿主及扩展描述文件")
    team = "UNSIGNED"
    if installable:
        team = read_profile(args.host_profile, HOST_ID, True)
        if read_profile(args.extension_profile, EXT_ID, False) != team:
            raise ValueError("宿主与扩展必须属于同一开发者团队")
    build = HERE / "build"
    build.mkdir(exist_ok=True)
    # A fresh staging folder avoids replacing a prior build or its signed assets.
    import tempfile
    stage = pathlib.Path(tempfile.mkdtemp(prefix="guard-", dir=build))
    cn_table = stage / "country-cn.txt"
    run(["cargo", "run", "--manifest-path", ROOT / "src-tauri/Cargo.toml", "--bin", "wujian-geo", "--locked", "--", "export-cn", args.mmdb.resolve(), cn_table])
    host = stage / "WujianGuard.app"
    extension = host / "Contents/Library/SystemExtensions" / f"{EXT_ID}.systemextension"
    for bundle in [host, extension]:
        (bundle / "Contents/MacOS").mkdir(parents=True, exist_ok=True)
        (bundle / "Contents/Resources").mkdir(exist_ok=True)
        shutil.copyfile(cn_table, bundle / "Contents/Resources/country-cn.txt")
    base = {"CFBundleDevelopmentRegion":"zh_CN", "CFBundleShortVersionString":"0.1.0", "CFBundleVersion":"1", "LSMinimumSystemVersion":"14.0"}
    write_plist(host / "Contents/Info.plist", {**base, "CFBundleIdentifier":HOST_ID, "CFBundleName":"WujianGuard", "CFBundleDisplayName":"无间道系统隔断验证", "CFBundleExecutable":"WujianGuard", "CFBundlePackageType":"APPL", "WujianInstallable":installable, "NSSystemExtensionUsageDescription":"安装本机网络过滤组件，在用户启用隔断时阻止非 CN 公网连接。"})
    write_plist(extension / "Contents/Info.plist", {**base, "CFBundleIdentifier":EXT_ID, "CFBundleName":"WujianPacketFilter", "CFBundleExecutable":"WujianPacketFilter", "CFBundlePackageType":"SYSX", "NetworkExtension":{"NEProviderClasses":{"com.apple.networkextension.filter-packet":"WujianPacketFilterProvider"}, "NEMachServiceName":f"{team}.{EXT_ID}"}})
    run(flags + ["-O", "-o", extension / "Contents/MacOS/WujianPacketFilter"] + extension_sources)
    run(flags + ["-O", "-o", host / "Contents/MacOS/WujianGuard"] + host_sources)
    ext_ent = {"com.apple.developer.networking.networkextension":[CAPABILITY], "com.apple.security.app-sandbox":True}
    host_ent = {"com.apple.developer.networking.networkextension":[CAPABILITY], "com.apple.developer.system-extension.install":True}
    if installable:
        for bundle, profile, ent, bundle_id in [(host,args.host_profile,host_ent,HOST_ID),(extension,args.extension_profile,ext_ent,EXT_ID)]:
            shutil.copyfile(profile,bundle / "Contents/embedded.provisionprofile")
            ent.update({"com.apple.developer.team-identifier":team,"com.apple.application-identifier":f"{team}.{bundle_id}"})
    for name, ent, bundle in [("extension",ext_ent,extension),("host",host_ent,host)]:
        path = stage / f"{name}.entitlements.plist"; write_plist(path, ent)
        sign = ["/usr/bin/codesign", "--force", "--sign", args.sign_identity if installable else "-", "--entitlements", path]
        if installable: sign += ["--options", "runtime", "--timestamp"]
        run(sign + [bundle])
    run(["/usr/bin/codesign", "--verify", "--deep", "--strict", host])
    print(f"Built: {host}")
    print("Installable signed package; user system authorization still required" if installable else "Compile-validation package only: installation is disabled")

if __name__ == "__main__":
    try: main()
    except (ValueError, OSError, subprocess.CalledProcessError) as e:
        print(f"Build failed: {e}",file=sys.stderr);sys.exit(1)
