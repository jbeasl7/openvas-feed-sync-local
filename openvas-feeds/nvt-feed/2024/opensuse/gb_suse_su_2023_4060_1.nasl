# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833332");
  script_version("2025-02-26T05:38:41+0000");
  script_cve_id("CVE-2023-42811");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-09-26 14:33:52 +0000 (Tue, 26 Sep 2023)");
  script_tag(name:"creation_date", value:"2024-03-04 07:33:37 +0000 (Mon, 04 Mar 2024)");
  script_name("openSUSE: Security Advisory for rage (SUSE-SU-2023:4060-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.5");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:4060-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/U6BLJXY6P4XEJWXHXMHZ7CSTDVTR5F2R");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'rage'
  package(s) announced via the SUSE-SU-2023:4060-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for rage-encryption fixes the following issues:

  - CVE-2023-42811: chosen ciphertext attack possible against aes-gcm (bsc#1215657)

  * update vendor.tar.zst to contain aes-gcm  = 0.10.3

  * Update to version 0.9.2+0:

  * CI: Ensure `apt` repository is up-to-date before installing build deps

  * CI: Build Linux releases using `ubuntu-20.04` runner

  * CI: Remove most uses of `actions-rs` actions

  * Update to version 0.9.2+0:

  * Fix changelog bugs and add missing entry

  * Document `PINENTRY_PROGRAM` environment variable

  * age: Add `Decryptor::new_async_buffered`

  * age: `impl AsyncBufRead for ArmoredReader`

  * Pre-initialize vectors when the capacity is known, or use arrays

  * Use `PINENTRY_PROGRAM` as environment variable for `pinentry`

  * Document why `impl AsyncWrite for StreamWriter` doesn't loop indefinitely

  * cargo update

  * cargo vet prune

  * Migrate to `cargo-vet 0.7`

  * build(deps): bump svenstaro/upload-release-action from 2.5.0 to 2.6.1

  * Correct spelling in documentation

  * build(deps): bump codecov/codecov-action from 3.1.1 to 3.1.4

  * StreamWriter AsyncWrite: fix usage with futures::io::copy()

  * rage: Use `Decryptor::new_buffered`

  * age: Add `Decryptor::new_buffered`

  * age: `impl BufRead for ArmoredReader`

  * Update Homebrew formula to v0.9.1

  * feat/pinentry: Use env var to define pinentry binary

  * Update to version 0.9.1+0:

  * ssh: Fix parsing of OpenSSH private key format

  * ssh: Support `aes256-gcm@openssh.com` ciphers for encrypted keys

  * ssh: Add `aes256-gcm@openssh.com` cipher to test cases

  * ssh: Extract common key material derivation logic for encrypted keys

  * ssh: Use associated constants for key and IV sizes

  * ssh: Add test cases for encrypted keys

  * Add shell completions for fish and zsh.

  ##");

  script_tag(name:"affected", value:"'rage' package(s) on openSUSE Leap 15.5.");

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

if(release == "openSUSELeap15.5") {

  if(!isnull(res = isrpmvuln(pkg:"rage-encryption", rpm:"rage-encryption~0.9.2+0~150500.3.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rage-encryption-debuginfo", rpm:"rage-encryption-debuginfo~0.9.2+0~150500.3.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rage-encryption-zsh-completion", rpm:"rage-encryption-zsh-completion~0.9.2+0~150500.3.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rage-encryption-bash-completion", rpm:"rage-encryption-bash-completion~0.9.2+0~150500.3.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rage-encryption-fish-completion", rpm:"rage-encryption-fish-completion~0.9.2+0~150500.3.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rage-encryption", rpm:"rage-encryption~0.9.2+0~150500.3.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rage-encryption-debuginfo", rpm:"rage-encryption-debuginfo~0.9.2+0~150500.3.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rage-encryption-zsh-completion", rpm:"rage-encryption-zsh-completion~0.9.2+0~150500.3.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rage-encryption-bash-completion", rpm:"rage-encryption-bash-completion~0.9.2+0~150500.3.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rage-encryption-fish-completion", rpm:"rage-encryption-fish-completion~0.9.2+0~150500.3.3.1", rls:"openSUSELeap15.5"))) {
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