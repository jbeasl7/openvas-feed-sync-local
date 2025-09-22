# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2020.3718.1");
  script_cve_id("CVE-2020-15436", "CVE-2020-15437", "CVE-2020-25669", "CVE-2020-27777", "CVE-2020-28915", "CVE-2020-28974", "CVE-2020-29371");
  script_tag(name:"creation_date", value:"2021-06-09 14:56:47 +0000 (Wed, 09 Jun 2021)");
  script_version("2024-02-02T14:37:50+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:50 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-06-04 11:55:41 +0000 (Fri, 04 Jun 2021)");

  script_name("SUSE: Security Advisory (SUSE-SU-2020:3718-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP1)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2020:3718-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2020/suse-su-20203718-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2020:3718-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 15 SP1 kernel was updated to receive various security and bugfixes.

The following security bugs were fixed:

CVE-2020-15436: Fixed a use after free vulnerability in fs/block_dev.c
 which could have allowed local users to gain privileges or cause a
 denial of service (bsc#1179141).

CVE-2020-15437: Fixed a null pointer dereference which could have
 allowed local users to cause a denial of service(bsc#1179140).

CVE-2020-25669: Fixed a use-after-free read in sunkbd_reinit()
 (bsc#1178182).

CVE-2020-27777: Restrict RTAS requests from userspace (bsc#1179107).

CVE-2020-28915: Fixed a buffer over-read in the fbcon code which could
 have been used by local attackers to read kernel memory (bsc#1178886).

CVE-2020-28974: Fixed a slab-out-of-bounds read in fbcon which could
 have been used by local attackers to read privileged information or
 potentially crash the kernel (bsc#1178589).

CVE-2020-29371: Fixed uninitialized memory leaks to userspace
 (bsc#1179429).

The following non-security bugs were fixed:

ACPI: GED: fix -Wformat (git-fixes).

ALSA: ctl: fix error path at adding user-defined element set (git-fixes).

ALSA: firewire: Clean up a locking issue in copy_resp_to_buf()
 (git-fixes).

ALSA: mixart: Fix mutex deadlock (git-fixes).

arm64: KVM: Fix system register enumeration (bsc#1174726).

arm/arm64: KVM: Add PSCI version selection API (bsc#1174726).

ASoC: qcom: lpass-platform: Fix memory leak (git-fixes).

ath10k: Acquire tx_lock in tx error paths (git-fixes).

batman-adv: set .owner to THIS_MODULE (git-fixes).

Bluetooth: btusb: Fix and detect most of the Chinese Bluetooth
 controllers (git-fixes).

Bluetooth: hci_bcm: fix freeing not-requested IRQ (git-fixes).

bpf: Zero-fill re-used per-cpu map element (git-fixes).

btrfs: account ticket size at add/delete time (bsc#1178897).

btrfs: add helper to obtain number of devices with ongoing dev-replace
 (bsc#1178897).

btrfs: check rw_devices, not num_devices for balance (bsc#1178897).

btrfs: do not delete mismatched root refs (bsc#1178962).

btrfs: fix btrfs_calc_reclaim_metadata_size calculation (bsc#1178897).

btrfs: fix force usage in inc_block_group_ro (bsc#1178897).

btrfs: fix invalid removal of root ref (bsc#1178962).

btrfs: fix reclaim counter leak of space_info objects (bsc#1178897).

btrfs: fix reclaim_size counter leak after stealing from global reserve
 (bsc#1178897).

btrfs: kill min_allocable_bytes in inc_block_group_ro (bsc#1178897).

btrfs: rework arguments of btrfs_unlink_subvol (bsc#1178962).

btrfs: split dev-replace locking helpers for read and write
 (bsc#1178897).

can: af_can: prevent potential access of uninitialized member in
 canfd_rcv() (git-fixes).

can: af_can: prevent potential access of uninitialized member in
 can_rcv() (git-fixes).

can: dev: can_restart(): post buffer from the right context (git-fixes).

can: gs_usb: fix endianness problem with candleLight ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise High Availability 15-SP1, SUSE Linux Enterprise Module for Basesystem 15-SP1, SUSE Linux Enterprise Module for Development Tools 15-SP1, SUSE Linux Enterprise Module for Legacy Software 15-SP1, SUSE Linux Enterprise Module for Live Patching 15-SP1, SUSE Linux Enterprise Workstation Extension 15-SP1.");

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

if(release == "SLES15.0SP1") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~4.12.14~197.75.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~4.12.14~197.75.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base-debuginfo", rpm:"kernel-default-base-debuginfo~4.12.14~197.75.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-debuginfo", rpm:"kernel-default-debuginfo~4.12.14~197.75.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-debugsource", rpm:"kernel-default-debugsource~4.12.14~197.75.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~4.12.14~197.75.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel-debuginfo", rpm:"kernel-default-devel-debuginfo~4.12.14~197.75.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-man", rpm:"kernel-default-man~4.12.14~197.75.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~4.12.14~197.75.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~4.12.14~197.75.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-zfcpdump-debuginfo", rpm:"kernel-zfcpdump-debuginfo~4.12.14~197.75.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-zfcpdump-debugsource", rpm:"kernel-zfcpdump-debugsource~4.12.14~197.75.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-docs", rpm:"kernel-docs~4.12.14~197.75.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-obs-build", rpm:"kernel-obs-build~4.12.14~197.75.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-obs-build-debugsource", rpm:"kernel-obs-build-debugsource~4.12.14~197.75.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~4.12.14~197.75.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~4.12.14~197.75.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"reiserfs-kmp-default", rpm:"reiserfs-kmp-default~4.12.14~197.75.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"reiserfs-kmp-default-debuginfo", rpm:"reiserfs-kmp-default-debuginfo~4.12.14~197.75.1", rls:"SLES15.0SP1"))) {
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
