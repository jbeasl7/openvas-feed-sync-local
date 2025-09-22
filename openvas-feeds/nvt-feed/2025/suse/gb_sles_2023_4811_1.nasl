# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2023.4811.1");
  script_cve_id("CVE-2023-31083", "CVE-2023-39197", "CVE-2023-39198", "CVE-2023-45863", "CVE-2023-45871", "CVE-2023-5717", "CVE-2023-6176");
  script_tag(name:"creation_date", value:"2025-02-13 14:53:48 +0000 (Thu, 13 Feb 2025)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-11-04 03:24:15 +0000 (Sat, 04 Nov 2023)");

  script_name("SUSE: Security Advisory (SUSE-SU-2023:4811-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:4811-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2023/suse-su-20234811-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1084909");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1210780");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1214037");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1214344");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1214764");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1215371");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1216058");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1216259");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1216584");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1216965");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1216976");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1217140");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1217332");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1217408");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1217780");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2023-December/017340.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2023:4811-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 15 SP3 kernel was updated to receive various security and bugfixes.


The following security bugs were fixed:

- CVE-2023-39197: Fixed a out-of-bounds read in nf_conntrack_dccp_packet() (bsc#1216976).
- CVE-2023-6176: Fixed a denial of service in the cryptographic algorithm scatterwalk functionality (bsc#1217332).
- CVE-2023-45863: Fixed a out-of-bounds write in fill_kobj_path() (bsc#1216058).
- CVE-2023-45871: Fixed an issue in the IGB driver, where the buffer size may not be adequate for frames larger than the MTU (bsc#1216259).
- CVE-2023-39198: Fixed a race condition leading to use-after-free in qxl_mode_dumb_create() (bsc#1216965).
- CVE-2023-31083: Fixed race condition in hci_uart_tty_ioctl (bsc#1210780).
- CVE-2023-5717: Fixed a heap out-of-bounds write vulnerability in the Performance Events component (bsc#1216584).

The following non-security bugs were fixed:

- ALSA: hda: Disable power-save on KONTRON SinglePC (bsc#1217140).
- Call flush_delayed_fput() from nfsd main-loop (bsc#1217408).
- net: mana: Configure hwc timeout from hardware (bsc#1214037).
- net: mana: Fix MANA VF unload when hardware is unresponsive (bsc#1214764).
- powerpc: Do not clobber f0/vs0 during fp<pipe>altivec register save (bsc#1217780).");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise Server 15-SP3, SUSE Linux Enterprise Server for SAP Applications 15-SP3.");

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

if(release == "SLES15.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-64kb", rpm:"kernel-64kb~5.3.18~150300.59.144.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-64kb-devel", rpm:"kernel-64kb-devel~5.3.18~150300.59.144.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~5.3.18~150300.59.144.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~5.3.18~150300.59.144.1.150300.18.84.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~5.3.18~150300.59.144.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~5.3.18~150300.59.144.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-docs", rpm:"kernel-docs~5.3.18~150300.59.144.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~5.3.18~150300.59.144.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-obs-build", rpm:"kernel-obs-build~5.3.18~150300.59.144.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-preempt", rpm:"kernel-preempt~5.3.18~150300.59.144.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-preempt-devel", rpm:"kernel-preempt-devel~5.3.18~150300.59.144.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~5.3.18~150300.59.144.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~5.3.18~150300.59.144.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-zfcpdump", rpm:"kernel-zfcpdump~5.3.18~150300.59.144.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"reiserfs-kmp-default", rpm:"reiserfs-kmp-default~5.3.18~150300.59.144.1", rls:"SLES15.0SP3"))) {
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
