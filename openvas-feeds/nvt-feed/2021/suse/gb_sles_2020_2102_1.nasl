# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2020.2102.1");
  script_cve_id("CVE-2020-0305", "CVE-2020-10135", "CVE-2020-10781", "CVE-2020-14331");
  script_tag(name:"creation_date", value:"2021-06-09 14:56:58 +0000 (Wed, 09 Jun 2021)");
  script_version("2024-02-02T14:37:50+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:50 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:P/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-09-22 15:47:57 +0000 (Tue, 22 Sep 2020)");

  script_name("SUSE: Security Advisory (SUSE-SU-2020:2102-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2020:2102-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2020/suse-su-20202102-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2020:2102-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 15 SP2 Azure kernel was updated to receive various security and bugfixes.


The following security bugs were fixed:

CVE-2020-10781: Fixed a denial of service issue in the ZRAM
 implementation (bnc#1173074).

CVE-2020-0305: In cdev_get of char_dev.c, there is a possible
 use-after-free due to a race condition. This could lead to local
 escalation of privilege with System execution privileges needed. User
 interaction is not needed for exploitation (bnc#1174462).

CVE-2020-10135: Legacy pairing and secure-connections pairing
 authentication in bluetooth may have allowed an unauthenticated user to
 complete authentication without pairing credentials via adjacent access.
 An unauthenticated, adjacent attacker could impersonate a Bluetooth
 BR/EDR master or slave to pair with a previously paired remote device to
 successfully complete the authentication procedure without knowing the
 link key (bnc#1171988).

CVE-2020-14331: Fixed a buffer over write in vgacon_scrollback_update()
 (bnc#1174205).

The following non-security bugs were fixed:

ACPICA: Dispatcher: add status checks (git-fixes).

ACPI/IORT: Fix PMCG node single ID mapping handling (git-fixes).

ACPI: video: Use native backlight on Acer Aspire 5783z (git-fixes).

ACPI: video: Use native backlight on Acer TravelMate 5735Z (git-fixes).

ALSA: hda: Intel: add missing PCI IDs for ICL-H, TGL-H and EKL
 (jsc#SLE-13261).

ALSA: hda/realtek - change to suitable link model for ASUS platform
 (git-fixes).

ALSA: hda/realtek: Enable headset mic of Acer TravelMate B311R-31 with
 ALC256 (git-fixes).

ALSA: hda/realtek: enable headset mic of ASUS ROG Zephyrus G14(G401)
 series with ALC289 (git-fixes).

ALSA: hda/realtek - Enable Speaker for ASUS UX533 and UX534 (git-fixes).

ALSA: hda/realtek - Enable Speaker for ASUS UX563 (git-fixes).

ALSA: hda/realtek: Fixed ALC298 sound bug by adding quirk for Samsung
 Notebook Pen S (git-fixes).

ALSA: hda/realtek - fixup for yet another Intel reference board
 (git-fixes).

ALSA: info: Drop WARN_ON() from buffer NULL sanity check (git-fixes).

ALSA: line6: Perform sanity check for each URB creation (git-fixes).

ALSA: line6: Sync the pending work cancel at disconnection (git-fixes).

ALSA: usb-audio: Add registration quirk for Kingston HyperX Cloud Flight
 S (git-fixes).

ALSA: usb-audio: Fix race against the error recovery URB submission
 (git-fixes).

apparmor: ensure that dfa state tables have entries (git-fixes).

apparmor: fix introspection of task mode for unconfined tasks
 (git-fixes).

apparmor: Fix memory leak of profile proxy (git-fixes).

apparmor: Fix use-after-free in aa_audit_rule_init (git-fixes).

apparmor: remove useless aafs_create_symlink (git-fixes).

arm64: dts: ls1043a-rdb: correct RGMII delay mode to rgmii-id
 (bsc#1174398).

arm64: dts: ls1046ardb: set RGMII interfaces to RGMII_ID mode
 (bsc#1174398).

ASoC: codecs: max98373: Removed ... [Please see the references for more information on the vulnerabilities]");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure", rpm:"kernel-azure~5.3.18~18.12.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-debuginfo", rpm:"kernel-azure-debuginfo~5.3.18~18.12.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-debugsource", rpm:"kernel-azure-debugsource~5.3.18~18.12.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-devel", rpm:"kernel-azure-devel~5.3.18~18.12.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-devel-debuginfo", rpm:"kernel-azure-devel-debuginfo~5.3.18~18.12.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel-azure", rpm:"kernel-devel-azure~5.3.18~18.12.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source-azure", rpm:"kernel-source-azure~5.3.18~18.12.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms-azure", rpm:"kernel-syms-azure~5.3.18~18.12.1", rls:"SLES15.0SP2"))) {
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
