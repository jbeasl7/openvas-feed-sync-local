# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2020.1146.1");
  script_cve_id("CVE-2019-19770", "CVE-2019-3701", "CVE-2019-9458", "CVE-2020-10942", "CVE-2020-11494", "CVE-2020-11669", "CVE-2020-8834");
  script_tag(name:"creation_date", value:"2021-06-09 14:57:04 +0000 (Wed, 09 Jun 2021)");
  script_version("2024-02-02T14:37:50+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:50 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-03-24 15:17:56 +0000 (Tue, 24 Mar 2020)");

  script_name("SUSE: Security Advisory (SUSE-SU-2020:1146-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP1)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2020:1146-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2020/suse-su-20201146-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2020:1146-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 15 SP1 kernel was updated to receive various security and bugfixes.

The following security bugs were fixed:

CVE-2020-8834: KVM on Power8 processors had a conflicting use of
 HSTATE_HOST_R1 to store r1 state in kvmppc_hv_entry plus in
 kvmppc_{save,restore}_tm, leading to a stack corruption. Because of
 this, an attacker with the ability to run code in kernel space of a
 guest VM can cause the host kernel to panic (bnc#1168276).

CVE-2020-11494: An issue was discovered in slc_bump in
 drivers/net/can/slcan.c, which allowed attackers to read uninitialized
 can_frame data, potentially containing sensitive information from kernel
 stack memory, if the configuration lacks CONFIG_INIT_STACK_ALL
 (bnc#1168424).

CVE-2020-10942: In get_raw_socket in drivers/vhost/net.c lacks
 validation of an sk_family field, which might allow attackers to trigger
 kernel stack corruption via crafted system calls (bnc#1167629).

CVE-2019-9458: In the video driver there was a use after free due to a
 race condition. This could lead to local escalation of privilege with no
 additional execution privileges needed (bnc#1168295).

CVE-2019-3701: Fixed an issue in can_can_gw_rcv, which could cause a
 system crash (bnc#1120386).

CVE-2019-19770: Fixed a use-after-free in the debugfs_remove function
 (bsc#1159198).

CVE-2020-11669: Fixed an issue where arch/powerpc/kernel/idle_book3s.S
 did not have save/restore functionality for PNV_POWERSAVE_AMR,
 PNV_POWERSAVE_UAMOR, and PNV_POWERSAVE_AMOR (bnc#1169390).

The following non-security bugs were fixed:

ACPICA: Introduce ACPI_ACCESS_BYTE_WIDTH() macro (bsc#1051510).

ACPI: watchdog: Fix gas->access_width usage (bsc#1051510).

ahci: Add support for Amazon's Annapurna Labs SATA controller
 (bsc#1169013).

ALSA: ali5451: remove redundant variable capture_flag (bsc#1051510).

ALSA: core: Add snd_device_get_state() helper (bsc#1051510).

ALSA: core: Replace zero-length array with flexible-array member
 (bsc#1051510).

ALSA: emu10k1: Fix endianness annotations (bsc#1051510).

ALSA: hda/ca0132 - Add Recon3Di quirk to handle integrated sound on EVGA
 X99 Classified motherboard (bsc#1051510).

ALSA: hda/ca0132 - Replace zero-length array with flexible-array member
 (bsc#1051510).

ALSA: hda_codec: Replace zero-length array with flexible-array member
 (bsc#1051510).

ALSA: hda: default enable CA0132 DSP support (bsc#1051510).

ALSA: hda: Fix potential access overflow in beep helper (bsc#1051510).

ALSA: hda/realtek - a fake key event is triggered by running shutup
 (bsc#1051510).

ALSA: hda/realtek - Enable headset mic of Acer X2660G with ALC662
 (git-fixes).

ALSA: hda/realtek: Enable mute LED on an HP system (bsc#1051510).

ALSA: hda/realtek - Enable the headset of Acer N50-600 with ALC662
 (git-fixes).

ALSA: hda/realtek: Fix pop noise on ALC225 (git-fixes).

ALSA: hda/realtek - Remove now-unnecessary XPS 13 headphone noise fixups
 ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise High Availability 15-SP1, SUSE Linux Enterprise Module for Basesystem 15-SP1, SUSE Linux Enterprise Module for Development Tools 15-SP1, SUSE Linux Enterprise Module for Legacy Software 15-SP1, SUSE Linux Enterprise Module for Live Patching 15-SP1, SUSE Linux Enterprise Module for Open Buildservice Development Tools 15-SP1, SUSE Linux Enterprise Workstation Extension 15-SP1.");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~4.12.14~197.40.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~4.12.14~197.40.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base-debuginfo", rpm:"kernel-default-base-debuginfo~4.12.14~197.40.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-debuginfo", rpm:"kernel-default-debuginfo~4.12.14~197.40.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-debugsource", rpm:"kernel-default-debugsource~4.12.14~197.40.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~4.12.14~197.40.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel-debuginfo", rpm:"kernel-default-devel-debuginfo~4.12.14~197.40.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-man", rpm:"kernel-default-man~4.12.14~197.40.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~4.12.14~197.40.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~4.12.14~197.40.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-zfcpdump-debuginfo", rpm:"kernel-zfcpdump-debuginfo~4.12.14~197.40.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-zfcpdump-debugsource", rpm:"kernel-zfcpdump-debugsource~4.12.14~197.40.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-docs", rpm:"kernel-docs~4.12.14~197.40.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-obs-build", rpm:"kernel-obs-build~4.12.14~197.40.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-obs-build-debugsource", rpm:"kernel-obs-build-debugsource~4.12.14~197.40.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~4.12.14~197.40.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~4.12.14~197.40.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"reiserfs-kmp-default", rpm:"reiserfs-kmp-default~4.12.14~197.40.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"reiserfs-kmp-default-debuginfo", rpm:"reiserfs-kmp-default-debuginfo~4.12.14~197.40.1", rls:"SLES15.0SP1"))) {
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
