# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2020.2980.1");
  script_cve_id("CVE-2020-12351", "CVE-2020-12352", "CVE-2020-24490", "CVE-2020-25641", "CVE-2020-25643", "CVE-2020-25645");
  script_tag(name:"creation_date", value:"2021-06-09 14:56:51 +0000 (Wed, 09 Jun 2021)");
  script_version("2024-02-02T14:37:50+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:50 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:P/I:P/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-11-30 17:14:46 +0000 (Mon, 30 Nov 2020)");

  script_name("SUSE: Security Advisory (SUSE-SU-2020:2980-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2020:2980-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2020/suse-su-20202980-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2020:2980-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 15 SP2 kernel was updated to receive various security and bugfixes.

The following security bugs were fixed:

CVE-2020-12351: Fixed a type confusion while processing AMP packets aka
 'BleedingTooth' aka 'BadKarma' (bsc#1177724).

CVE-2020-24490: Fixed a heap buffer overflow when processing extended
 advertising report events aka 'BleedingTooth' aka 'BadVibes'
 (bsc#1177726).

CVE-2020-12352: Fixed an information leak when processing certain AMP
 packets aka 'BleedingTooth' aka 'BadChoice' (bsc#1177725).

CVE-2020-25641: Fixed a zero-length biovec request issued by the block
 subsystem could have caused the kernel to enter an infinite loop,
 causing a denial of service (bsc#1177121).

CVE-2020-25643: Fixed a memory corruption and a read overflow which
 could have caused by improper input validation in the ppp_cp_parse_cr
 function (bsc#1177206).

CVE-2020-25645: Fixed an issue which traffic between two Geneve
 endpoints may be unencrypted when IPsec is configured to encrypt traffic
 for the specific UDP port used by the GENEVE tunnel allowing anyone
 between the two endpoints to read the traffic unencrypted (bsc#1177511).

The following non-security bugs were fixed:

9p: Fix memory leak in v9fs_mount (git-fixes).

ACPI: EC: Reference count query handlers under lock (git-fixes).

airo: Fix read overflows sending packets (git-fixes).

ar5523: Add USB ID of SMCWUSBT-G2 wireless adapter (git-fixes).

arm64: Enable PCI write-combine resources under sysfs (bsc#1175807).

ASoC: img-i2s-out: Fix runtime PM imbalance on error (git-fixes).

ASoC: Intel: bytcr_rt5640: Add quirk for MPMAN Converter9 2-in-1
 (git-fixes).

ASoC: kirkwood: fix IRQ error handling (git-fixes).

ASoC: wm8994: Ensure the device is resumed in wm89xx_mic_detect
 functions (git-fixes).

ASoC: wm8994: Skip setting of the WM8994_MICBIAS register for WM1811
 (git-fixes).

ata: ahci: mvebu: Make SATA PHY optional for Armada 3720 (git-fixes).

ath10k: fix array out-of-bounds access (git-fixes).

ath10k: fix memory leak for tpc_stats_final (git-fixes).

ath10k: use kzalloc to read for ath10k_sdio_hif_diag_read (git-fixes).

Bluetooth: Fix refcount use-after-free issue (git-fixes).

Bluetooth: guard against controllers sending zero'd events (git-fixes).

Bluetooth: Handle Inquiry Cancel error after Inquiry Complete
 (git-fixes).

Bluetooth: L2CAP: handle l2cap config request during open state
 (git-fixes).

Bluetooth: prefetch channel before killing sock (git-fixes).

brcmfmac: Fix double freeing in the fmac usb data path (git-fixes).

btrfs: block-group: do not set the wrong READA flag for
 btrfs_read_block_groups() (bsc#1176019).

btrfs: block-group: fix free-space bitmap threshold (bsc#1176019).

btrfs: block-group: refactor how we delete one block group item
 (bsc#1176019).

btrfs: block-group: refactor how we insert a block group item
 (bsc#1176019).

btrfs: block-group: refactor how we ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise High Availability 15-SP2, SUSE Linux Enterprise Module for Basesystem 15-SP2, SUSE Linux Enterprise Module for Development Tools 15-SP2, SUSE Linux Enterprise Module for Legacy Software 15-SP2, SUSE Linux Enterprise Module for Live Patching 15-SP2, SUSE Linux Enterprise Workstation Extension 15-SP2.");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~5.3.18~24.29.2", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~5.3.18~24.29.2.9.9.3", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-debuginfo", rpm:"kernel-default-debuginfo~5.3.18~24.29.2", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-debugsource", rpm:"kernel-default-debugsource~5.3.18~24.29.2", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~5.3.18~24.29.2", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel-debuginfo", rpm:"kernel-default-devel-debuginfo~5.3.18~24.29.2", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~5.3.18~24.29.2", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~5.3.18~24.29.2", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-preempt", rpm:"kernel-preempt~5.3.18~24.29.2", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-preempt-debuginfo", rpm:"kernel-preempt-debuginfo~5.3.18~24.29.2", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-preempt-debugsource", rpm:"kernel-preempt-debugsource~5.3.18~24.29.2", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-docs", rpm:"kernel-docs~5.3.18~24.29.2", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-obs-build", rpm:"kernel-obs-build~5.3.18~24.29.2", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-obs-build-debugsource", rpm:"kernel-obs-build-debugsource~5.3.18~24.29.2", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-preempt-devel", rpm:"kernel-preempt-devel~5.3.18~24.29.2", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-preempt-devel-debuginfo", rpm:"kernel-preempt-devel-debuginfo~5.3.18~24.29.2", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~5.3.18~24.29.2", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~5.3.18~24.29.2", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"reiserfs-kmp-default", rpm:"reiserfs-kmp-default~5.3.18~24.29.2", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"reiserfs-kmp-default-debuginfo", rpm:"reiserfs-kmp-default-debuginfo~5.3.18~24.29.2", rls:"SLES15.0SP2"))) {
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
