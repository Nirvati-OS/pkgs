"""
Script to filter JSON output of kconfig hardened check script.
"""

import json
import sys

"""
Names of check groups we analyze.
"""
GROUPS = {'defconfig', 'kspp'}

"""
Names of violations we ignore for a good reason.
"""
IGNORE_VIOLATIONS = {
    'CONFIG_MODULES', # enabled for backwards compat, modules require signing key which is thrown away
    'CONFIG_BINFMT_MISC', # build as module, can only be loaded explicitly
    'CONFIG_DEBUG_VIRTUAL', # disabled due to performance reasons
    'CONFIG_RANDSTRUCT_FULL', # disabled due to performance reasons
    'CONFIG_INET_DIAG', # last vulnerability prior to v4.1. Required for CNIs such as Cilium to terminate sockets. (https://github.com/siderolabs/pkgs/issues/1028)
    'CONFIG_IOMMU_DEFAULT_DMA_STRICT', # performance impact https://github.com/siderolabs/talos/issues/9531
    'CONFIG_GCC_PLUGIN_LATENT_ENTROPY', # doesn't seem very relevant, entropy is low quality, and not available in Clang, https://github.com/torvalds/linux/blob/37a93dd5c49b5fda807fd204edf2547c3493319c/scripts/gcc-plugins/Kconfig#L25-L33
    'CONFIG_IOMMU_DEFAULT_DMA_LAZY', # performance impact, we can reconsider later
    'CONFIG_CFI_CLANG', # Renamed to CONFIG_CFI in v6.18
    'CONFIG_CFI_PERMISSIVE' # TODO: We have this set, idk why it fails to be detected
}

"""
Names of violations per arch we ignore for a good reason.
"""
IGNORE_VIOLATIONS_BY_ARCH = {
    'arm64': {
        'CONFIG_DEFAULT_MMAP_MIN_ADDR', # looks to be a bug in the kernel-hardening-checker, the config is set in kernel config
        'CONFIG_LSM_MMAP_MIN_ADDR', # on arm64, this can be set only to 32768: https://cateee.net/lkddb/web-lkddb/LSM_MMAP_MIN_ADDR.html
        'CONFIG_RODATA_FULL_DEFAULT_ENABLED', # removed in 6.18
        'CONFIG_KASAN_HW_TAGS', # incompatible with OpenZFS and NVIDIA due to 'GPL-incompatible module nvidia.ko uses GPL-only symbol 'kasan_flag_enabled''
        'CONFIG_ARM64_PAN', # Removed since v7.0
    },
    'amd64': {
        #'CONFIG_CFI_AUTO_DEFAULT', # Disabled due to issues with GPL-incompatible modules
    },
}

def main():
    if len(sys.argv) != 2:
        print("Usage: {} <arch>".format(sys.argv[0]))

        sys.exit(1)

    arch = sys.argv[1]

    violations = json.load(sys.stdin)

    # filter out non-failures
    violations = [item for item in violations if item["check_result"].startswith("FAIL")]

    # filter only failures in the groups we're interested in
    violations = [item for item in violations if item["decision"] in GROUPS]

    # add violations we ignore per arch
    IGNORE_VIOLATIONS.update(IGNORE_VIOLATIONS_BY_ARCH[arch])

    # filter out violations we ignore
    violations = [item for item in violations if item["option_name"] not in IGNORE_VIOLATIONS]

    if not violations:
        sys.exit(0)

    print('{:^45}|{:^13}|{:^10}|{:^20}'.format('option name', 'desired val', 'decision', 'reason'))
    print('=' * 91)

    for item in violations:
        print('{:<45}|{:^13}|{:^10}|{:^20}'.format(item["option_name"], item["desired_val"], item["decision"],item["reason"]))

    sys.exit(1)


if __name__ == "__main__":
    main()
