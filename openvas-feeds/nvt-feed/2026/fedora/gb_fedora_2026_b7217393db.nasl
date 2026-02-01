# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2026.98721739310098");
  script_cve_id("CVE-2025-69277");
  script_tag(name:"creation_date", value:"2026-01-12 04:26:16 +0000 (Mon, 12 Jan 2026)");
  script_version("2026-01-12T05:50:06+0000");
  script_tag(name:"last_modification", value:"2026-01-12 05:50:06 +0000 (Mon, 12 Jan 2026)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Fedora: Security Advisory (FEDORA-2026-b7217393db)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC42");

  script_xref(name:"Advisory-ID", value:"FEDORA-2026-b7217393db");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2026-b7217393db");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2426617");
  script_xref(name:"URL", value:"https://ipcrypt-std.github.io");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libsodium' package(s) announced via the FEDORA-2026-b7217393db advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"**Version 1.0.21**

 This point release includes all the changes from 1.0.20-stable, which
include a security fix for the `crypto_core_ed25519_is_valid_point()`
function, as well as two new sets of functions:

 - The new `crypto_ipcrypt_*` functions implement mechanisms for securely
encrypting and anonymizing IP addresses as specified in [link moved to references]
 - The `sodium_bin2ip` and `sodium_ip2bin` helper functions have been added
to complement the `crypto_ipcrypt_*` functions and easily convert addresses
between bytes and strings.
 - XOF: the `crypto_xof_shake*` and `crypto_xof_turboshake*` functions
are standard extendable output functions. From input of any length, they can
derive output of any length with the same properties as hash functions. These
primitives are required by many post-quantum mechanisms, but can also be used
for a wide range of applications, including key derivation, session encryption
and more.

----

**Version 1.0.20-stable**

 - XCFramework: cross-compilation is now forced on Apple Silicon to
avoid Rosetta-related build issues
 - The Fil-C compiler is supported out of the box
 - The CompCert compiler is supported out of the box
 - MSVC 2026 (Visual Studio 2026) is now supported
 - Zig builds now support FreeBSD targets
 - Performance of AES256-GCM and AEGIS on ARM has been improved
with some compilers
 - Android binaries have been added to the NuGet package
 - Windows ARM binaries have been added to the NuGet package
 - The Android build script has been improved. The base SDK is
now 27c, and the default platform is 21, supporting 16 KB page sizes.
 - The library can now be compiled with Zig 0.15 and Zig 0.16
 - Zig builds now generate position-independent static libraries by
default on targets that support PIC
 - arm64e builds have been added to the XCFramework packages
 - XCFramework packages are now full builds instead of minimal
builds
 - MSVC builds have been enabled for ARM64
 - iOS 32-bit (armv7/armv7s) support has been removed from the
XCFramework build script
 - Security: optblockers have been introduced in critical code paths
to prevent compilers from introducing unwanted side channels via
conditional jumps. This was observed on RISC-V targets with specific
compilers and options.
 - Security: `crypto_core_ed25519_is_valid_point()` now properly
rejects small-order points that are not in the main subgroup
 - `((nonnull))` attributes have been relaxed on some `crypto_stream*`
functions to allow NULL output buffers when the output length is zero
 - A cross-compilation issue with old clang versions has been
fixed
 - JavaScript: support for Cloudflare Workers has been added
 - JavaScript: WASM_BIGINT is forcibly disabled to retain
compatibility with older runtimes
 - A compilation issue with old toolchains on Solaris has been
fixed
 - `crypto_aead_aes256gcm_is_available` is exported to JavaScript
 - libsodium is now compatible with ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'libsodium' package(s) on Fedora 42.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "FC42") {

  if(!isnull(res = isrpmvuln(pkg:"libsodium", rpm:"libsodium~1.0.21~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsodium-debuginfo", rpm:"libsodium-debuginfo~1.0.21~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsodium-debugsource", rpm:"libsodium-debugsource~1.0.21~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsodium-devel", rpm:"libsodium-devel~1.0.21~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsodium-static", rpm:"libsodium-static~1.0.21~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw32-libsodium", rpm:"mingw32-libsodium~1.0.21~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw32-libsodium-debuginfo", rpm:"mingw32-libsodium-debuginfo~1.0.21~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw64-libsodium", rpm:"mingw64-libsodium~1.0.21~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw64-libsodium-debuginfo", rpm:"mingw64-libsodium-debuginfo~1.0.21~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

exit(0);
