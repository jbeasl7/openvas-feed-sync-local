# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2020.3713.1");
  script_cve_id("CVE-2020-15436", "CVE-2020-15437", "CVE-2020-25668", "CVE-2020-25669", "CVE-2020-25704", "CVE-2020-27777", "CVE-2020-28368", "CVE-2020-28915", "CVE-2020-28941", "CVE-2020-28974", "CVE-2020-29369", "CVE-2020-29371", "CVE-2020-4788", "CVE-2020-8694", "CVE-2020-8695");
  script_tag(name:"creation_date", value:"2021-06-09 14:56:48 +0000 (Wed, 09 Jun 2021)");
  script_version("2024-02-02T14:37:50+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:50 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-06-04 11:55:41 +0000 (Fri, 04 Jun 2021)");

  script_name("SUSE: Security Advisory (SUSE-SU-2020:3713-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2020:3713-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2020/suse-su-20203713-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2020:3713-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 15 SP2 Azure kernel was updated to receive various security and bugfixes.

The following security bugs were fixed:

CVE-2020-15436: Fixed a use after free vulnerability in fs/block_dev.c
 which could have allowed local users to gain privileges or cause a
 denial of service (bsc#1179141).

CVE-2020-15437: Fixed a null pointer dereference which could have
 allowed local users to cause a denial of service(bsc#1179140).

CVE-2020-25668: Fixed a concurrency use-after-free in con_font_op
 (bsc#1178123).

CVE-2020-25669: Fixed a use-after-free read in sunkbd_reinit()
 (bsc#1178182).

CVE-2020-25704: Fixed a leak in perf_event_parse_addr_filter()
 (bsc#1178393).

CVE-2020-27777: Restrict RTAS requests from userspace (bsc#1179107)

CVE-2020-28915: Fixed a buffer over-read in the fbcon code which could
 have been used by local attackers to read kernel memory (bsc#1178886).

CVE-2020-28941: Fixed an issue where local attackers on systems with the
 speakup driver could cause a local denial of service attack
 (bsc#1178740).

CVE-2020-28974: Fixed a slab-out-of-bounds read in fbcon which could
 have been used by local attackers to read privileged information or
 potentially crash the kernel (bsc#1178589).

CVE-2020-29371: Fixed uninitialized memory leaks to userspace
 (bsc#1179429).

CVE-2020-4788: Fixed an issue with IBM Power9 processors could have
 allowed a local user to obtain sensitive information from the data in
 the L1 cache under extenuating circumstances (bsc#1177666).

CVE-2020-8694, CVE-2020-8695: Fixed an insufficient access control in
 the Linux kernel driver for some Intel(R) Processors which might have
 allowed an authenticated user to potentially enable information
 disclosure via local access (bsc#1170415 bsc#1170446)

CVE-2020-28368: Fixed Intel RAPL sidechannel attack aka PLATYPUS attack
 (XSA-351 bsc#1178591).

CVE-2020-29369: Fixed a race condition between certain expand functions
 (expand_downwards and expand_upwards) and page-table free operations
 from an munmap call, aka CID-246c320a8cfe (bnc#1173504 bsc#1179432).

The following non-security bugs were fixed:

9P: Cast to loff_t before multiplying (git-fixes).

ACPI: button: Add DMI quirk for Medion Akoya E2228T (git-fixes).

ACPICA: Add NHLT table signature (bsc#1176200).

ACPI: dock: fix enum-conversion warning (git-fixes).

ACPI / extlog: Check for RDMSR failure (git-fixes).

ACPI: GED: fix -Wformat (git-fixes).

ACPI: NFIT: Fix comparison to '-ENXIO' (git-fixes).

ACPI: video: use ACPI backlight for HP 635 Notebook (git-fixes).

Add bug reference to two hv_netvsc patches (bsc#1178853).

ALSA: ctl: fix error path at adding user-defined element set (git-fixes).

ALSA: firewire: Clean up a locking issue in copy_resp_to_buf()
 (git-fixes).

ALSA: fix kernel-doc markups (git-fixes).

ALSA: hda: fix jack detection with Realtek codecs when in D3 (git-fixes).

ALSA: hda: prevent ... [Please see the references for more information on the vulnerabilities]");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure", rpm:"kernel-azure~5.3.18~18.29.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-debuginfo", rpm:"kernel-azure-debuginfo~5.3.18~18.29.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-debugsource", rpm:"kernel-azure-debugsource~5.3.18~18.29.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-devel", rpm:"kernel-azure-devel~5.3.18~18.29.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-devel-debuginfo", rpm:"kernel-azure-devel-debuginfo~5.3.18~18.29.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel-azure", rpm:"kernel-devel-azure~5.3.18~18.29.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source-azure", rpm:"kernel-source-azure~5.3.18~18.29.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms-azure", rpm:"kernel-syms-azure~5.3.18~18.29.1", rls:"SLES15.0SP2"))) {
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
