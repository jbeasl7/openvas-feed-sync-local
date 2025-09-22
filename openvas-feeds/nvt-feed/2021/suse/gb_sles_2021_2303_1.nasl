# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2021.2303.1");
  script_cve_id("CVE-2020-26558", "CVE-2020-36385", "CVE-2020-36386", "CVE-2021-0129", "CVE-2021-0512", "CVE-2021-0605", "CVE-2021-33624", "CVE-2021-34693", "CVE-2021-3573");
  script_tag(name:"creation_date", value:"2021-07-14 02:21:14 +0000 (Wed, 14 Jul 2021)");
  script_version("2024-02-02T14:37:50+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:50 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-08-24 19:21:41 +0000 (Tue, 24 Aug 2021)");

  script_name("SUSE: Security Advisory (SUSE-SU-2021:2303-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2021:2303-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2021/suse-su-20212303-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2021:2303-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 15 SP2 Azure kernel was updated to receive various security and bugfixes.


The following security bugs were fixed:

CVE-2021-3573: Fixed an UAF vulnerability in function that can allow
 attackers to corrupt kernel heaps and adopt further exploitations.
 (bsc#1186666)

CVE-2021-0605: Fixed an out-of-bounds read which could lead to local
 information disclosure in the kernel with System execution privileges
 needed. (bsc#1187601)

CVE-2021-0512: Fixed a possible out-of-bounds write which could lead to
 local escalation of privilege with no additional execution privileges
 needed. (bsc#1187595)

CVE-2021-33624: Fixed a bug which allows unprivileged BPF program to
 leak the contents of arbitrary kernel memory (and therefore, of all
 physical memory) via a side-channel. (bsc#1187554)

CVE-2021-34693: Fixed a bug in net/can/bcm.c which could allow local
 users to obtain sensitive information from kernel stack memory because
 parts of a data structure are uninitialized. (bsc#1187452)

CVE-2021-0129: Fixed improper access control in BlueZ that may have
 allowed an authenticated user to potentially enable information
 disclosure via adjacent access (bnc#1186463).

CVE-2020-36385: Fixed a use-after-free via the ctx_list in some
 ucma_migrate_id situations where ucma_close is called (bnc#1187050).

CVE-2020-26558: Fixed Bluetooth LE and BR/EDR secure pairing in
 Bluetooth Core Specification 2.1 (bnc#1179610, bnc#1186463).

CVE-2020-36386: Fixed an out-of-bounds read issue in
 hci_extended_inquiry_result_evt (bnc#1187038).

The following non-security bugs were fixed:

acpica: Clean up context mutex during object deletion (git-fixes).

alsa: hda/cirrus: Set Initial DMIC volume to -26 dB (git-fixes).

alsa: hda: Fix for mute key LED for HP Pavilion 15-CK0xx (git-fixes).

alsa: timer: Fix master timer notification (git-fixes).

alx: Fix an error handling path in 'alx_probe()' (git-fixes).

arch: Add arch-dependent support markers in supported.conf (bsc#1186672)

arch: Add the support for kernel-FLAVOR-optional subpackage
 (jsc#SLE-11796)

ASoC: Intel: bytcr_rt5640: Add quirk for the Glavey TM800A550L tablet
 (git-fixes).

ASoC: Intel: bytcr_rt5640: Add quirk for the Lenovo Miix 3-830 tablet
 (git-fixes).

ASoC: max98088: fix ni clock divider calculation (git-fixes).

ASoC: rt5659: Fix the lost powers for the HDA header (git-fixes).

ASoC: sti-sas: add missing MODULE_DEVICE_TABLE (git-fixes).

ath6kl: return error code in ath6kl_wmi_set_roam_lrssi_cmd() (git-fixes).

batman-adv: Avoid WARN_ON timing related checks (git-fixes).

be2net: Fix an error handling path in 'be_probe()' (git-fixes).

blk-settings: align max_sectors on 'logical_block_size' boundary
 (bsc#1185195).

block: Discard page cache of zone reset target range (bsc#1187402).

block: return the correct bvec when checking for gaps (bsc#1187143).

block: return the correct bvec when checking for ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise Module for Public Cloud 15-SP2.");

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

if(release == "SLES15.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure", rpm:"kernel-azure~5.3.18~18.53.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-debuginfo", rpm:"kernel-azure-debuginfo~5.3.18~18.53.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-debugsource", rpm:"kernel-azure-debugsource~5.3.18~18.53.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-devel", rpm:"kernel-azure-devel~5.3.18~18.53.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-devel-debuginfo", rpm:"kernel-azure-devel-debuginfo~5.3.18~18.53.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel-azure", rpm:"kernel-devel-azure~5.3.18~18.53.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source-azure", rpm:"kernel-source-azure~5.3.18~18.53.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms-azure", rpm:"kernel-syms-azure~5.3.18~18.53.1", rls:"SLES15.0SP2"))) {
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
