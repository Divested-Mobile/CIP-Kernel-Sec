# -*- shell-script -*-

_cat_kconfig() {
    local release

    if [ -f /proc/config ]; then
	cat /proc/config
    elif [ -f /proc/config.gz ]; then
	gzip -dc /proc/config.gz
    elif [ -f /boot/config-"${release:=$(uname -r)}" ]; then
	cat /boot/config-"$release"
    else
	return 1
    fi
}

# Check symbol state in kernel config.
# Parameters:
# - symbol name (required)
# - symbol state (optional), one of m n y
# If symbol state is not specified then both m and y will be accepted.
check_kconfig() {
    local regexp

    if [ $# -eq 1 ]; then
	regexp="^$1="
    elif [ "$2" = n ]; then
	regexp="^# $1 is not"
    else
	regexp="^$1=$2"
    fi
    _cat_kconfig | grep -q "$regexp"
}

assert_kconfig() {
    if check_kconfig "$@"; then
	return
    fi
    if [ $# -eq 1 ]; then
	echo >&2 "E: $1 must be enabled"
    elif [ "$2" = n ]; then
	echo >&2 "E: $1 must be disabled"
    else
	echo >&2 "E: $1 must be set to $2"
    fi
    exit 1
}

# Assert that no unexpected taint flags are set.  By default this ignores
# TAINT_CRAP, TAINT_FIRMWARE_WORKAROUND, TAINT_OOT_MODULE,
# TAINT_UNSIGNED_MODULE, TAINT_LIVEPATCH.
# Parameters:
# - bitmask of extra flags to ignore (optional)
assert_untainted() {
    local tainted

    tainted="$(cat /proc/sys/kernel/tainted)"
    tainted="$((tainted & ~(0xbc00 | ${1:-0})))"

    if [ $tainted -eq 0 ]; then
	return
    fi

    printf >&2 'E: Unexpected taint flags: %#x\n' $tainted
    exit 1
}

# Temporary files should normally be created under this directory, which
# is automatically cleaned up.
scratch_dir="$(mktemp -d)"

common_cleanup() {
    rm -rf "$scratch_dir"
}

# The test_cleanup function should be redefined by tests that need any
# special cleanup.
test_cleanup() {
    :
}

cleanup() {
    test_cleanup
    common_cleanup
}
trap cleanup EXIT
