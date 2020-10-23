test_cleanup() {
    if mountpoint -q "$scratch_dir/mnt"; then
	umount "$scratch_dir/mnt"
    fi
}

bobfuzzer_url() {
    local cve_id="$1"
    local ext="$2"
    local basename="$(echo "$cve_id" | sed 's/^CVE-/poc_/;s/-/_/')"

    echo "https://raw.githubusercontent.com/bobfuzzer/CVE/master/$cve_id/$basename$ext"
}

_bobfuzzer_mount() {
    local cve_id="$1"
    local fstype="$2"

    curl -o "$scratch_dir/poc.zip" "$(bobfuzzer_url "$cve_id" .zip)" || return 2
    unzip -p "$scratch_dir/poc.zip" > "$scratch_dir/poc.img" || return 2
    mkdir -p "$scratch_dir/mnt" || return 2
    mount -o loop -t "$fstype" "$scratch_dir/poc.img" "$scratch_dir/mnt" || return 1
}

# Attempt to mount invalid image.  Fixed kernel should accept it,
# without warnings.
bobfuzzer_mount_accept() {
    if _bobfuzzer_mount "$@"; then
	:
    elif [ $? -gt 1 ]; then
	echo >&2 "E: Mount preparation failed"
	exit 1
    else
	echo >&2 "E: Mount failed"
	exit 1
    fi
}

# Attempt to mount invalid image.  Fixed kernel should reject it at
# mount time, without warnings.
bobfuzzer_mount_reject() {
    if _bobfuzzer_mount "$@"; then
	echo >&2 "E: Mount succeeded but should have been rejected"
	exit 1
    elif [ $? -gt 1 ]; then
	echo >&2 "E: Mount preparation failed"
	exit 1
    fi
}

# Attempt to mount and manipulate invalid image.  Fixed kernel may
# reject it at mount time or later, without warnings.
bobfuzzer_mount_and_run() {
    local cve_id="$1"
    local fstype="$2"

    if _bobfuzzer_mount "$@"; then
	curl -o "$scratch_dir/poc.c" "$(bobfuzzer_url "$cve_id" .c)"
	cc -o "$scratch_dir/poc" "$scratch_dir/poc.c"
	(cd "$scratch_dir/mnt" && ../poc) || true
    elif [ $? -gt 1 ]; then
	echo >&2 "E: Mount preparation failed"
	exit 1
    fi
}
