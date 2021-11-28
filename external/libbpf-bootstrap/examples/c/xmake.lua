add_rules("mode.release", "mode.debug")
add_rules("platform.linux.bpf")
set_license("GPL-2.0")

if xmake.version():satisfies(">=2.5.7 <=2.5.9") then
    on_load(function (target)
        raise("xmake(%s) has a bug preventing BPF source code compilation. Please run `xmake update -f 2.5.6` to revert to v2.5.6 version or upgrade to xmake v2.6.1 that fixed the issue.", xmake.version())
    end)
end

option("system-libbpf",      {showmenu = true, default = false, description = "Use system-installed libbpf"})
option("require-bpftool",    {showmenu = true, default = false, description = "Require bpftool package"})

add_requires("libelf", "zlib")
if is_plat("android") then
    add_requires("ndk >=22.x", "argp-standalone")
    set_toolchains("@ndk", {sdkver = "23"})
else
    add_requires("llvm >=10.x")
    set_toolchains("@llvm")
    add_requires("linux-headers")
end

add_includedirs("../../vmlinux")

-- we can run `xmake f --require-bpftool=y` to pull bpftool from xmake-repo repository
if has_config("require-bpftool") then
    add_requires("linux-tools", {configs = {bpftool = true}})
    add_packages("linux-tools")
else
    before_build(function (target)
        os.addenv("PATH", path.join(os.scriptdir(), "..", "..", "tools"))
    end)
end

-- we use the vendored libbpf sources for libbpf-bootstrap.
-- for some projects you may want to use the system-installed libbpf, so you can run `xmake f --system-libbpf=y`
if has_config("system-libbpf") then
    add_requires("libbpf", {system = true})
else
    target("libbpf")
        set_kind("static")
        set_basename("bpf")
        add_files("../../libbpf/src/*.c")
        add_includedirs("../../libbpf/include")
        add_includedirs("../../libbpf/include/uapi", {public = true})
        add_includedirs("$(buildir)", {interface = true})
        add_configfiles("../../libbpf/src/(*.h)", {prefixdir = "bpf"})
        add_packages("libelf", "zlib")
        if is_plat("android") then
            add_defines("__user=", "__force=", "__poll_t=uint32_t")
        end
end

target("minimal")
    set_kind("binary")
    add_files("minimal*.c")
    add_packages("linux-headers")
    if not has_config("system-libbpf") then
        add_deps("libbpf")
    end

target("bootstrap")
    set_kind("binary")
    add_files("bootstrap*.c")
    add_packages("linux-headers")
    if not has_config("system-libbpf") then
        add_deps("libbpf")
    end
    if is_plat("android") then
        add_packages("argp-standalone")
    end

target("fentry")
    set_kind("binary")
    add_files("fentry*.c")
    add_packages("linux-headers")
    if not has_config("system-libbpf") then
        add_deps("libbpf")
    end

target("uprobe")
    set_kind("binary")
    add_files("uprobe*.c")
    add_packages("linux-headers")
    if not has_config("system-libbpf") then
        add_deps("libbpf")
    end

target("kprobe")
    set_kind("binary")
    add_files("kprobe*.c")
    add_packages("linux-headers")
    if not has_config("system-libbpf") then
        add_deps("libbpf")
    end
    if is_plat("android") then
        -- TODO we need fix vmlinux.h to support android
        set_default(false)
    end
