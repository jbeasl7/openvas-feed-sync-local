# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2025.03271.1");
  script_cve_id("CVE-2023-42363", "CVE-2023-42364", "CVE-2023-42365");
  script_tag(name:"creation_date", value:"2025-09-22 04:12:25 +0000 (Mon, 22 Sep 2025)");
  script_version("2025-09-22T07:08:28+0000");
  script_tag(name:"last_modification", value:"2025-09-22 07:08:28 +0000 (Mon, 22 Sep 2025)");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-11-30 05:08:08 +0000 (Thu, 30 Nov 2023)");

  script_name("SUSE: Security Advisory (SUSE-SU-2025:03271-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP5|SLES15\.0SP6)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:03271-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-202503271-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1203397");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1203399");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1206798");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1215943");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1217580");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1217584");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1217585");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1217883");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1239176");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1243201");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-updates/2025-September/041774.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'busybox, busybox-links' package(s) announced via the SUSE-SU-2025:03271-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for busybox, busybox-links fixes the following issues:

Updated to version 1.37.0 (jsc#PED-13039):

 - CVE-2023-42363: Fixed use-after-free vulnerability in xasprintf function in xfuncs_printf.c (bsc#1217580)
 - CVE-2023-42364: Fixed use-after-free in the awk.c evaluate function (bsc#1217584)
 - CVE-2023-42365: Fixed use-after-free in the awk.c copyvar function (bsc#1217585)

Other fixes:

 - fix generation of file lists via Dockerfile
 - add copy of busybox.links from the container to catch changes
 to busybox config
 - Blacklist creating links for halt, reboot, shutdown commands to avoid accidental
 use in a fully booted system (bsc#1243201)
 - Add getfattr applet to attr filelist
 - busybox-udhcpc conflicts with udhcp.
 - Add new sub-package for udhcpc
 - zgrep: don't set the label option as only the real grep
 supports it (bsc#1215943)
 - Add conflict for coreutils-systemd, package got splitted
 - Check in filelists instead of buildrequiring all non-busybox utils
 - Replace transitional %usrmerged macro with regular version check (bsc#1206798)
 - Create sub-package 'hexedit' [bsc#1203399]
 - Create sub-package 'sha3sum' [bsc#1203397]
 - Drop update-alternatives support
 - Add provides smtp_daemon to busybox-sendmail
 - Add conflicts: mawk to busybox-gawk
 - fix mkdir path to point to /usr/bin instead of /bin
 - add placeholder variable and ignore applet logic to busybox.install
 - enable halt, poweroff, reboot commands (bsc#1243201)
 - Fully enable udhcpc and document that this tool needs special
 configuration and does not work out of the box [bsc#1217883]
 - Replace transitional %usrmerged macro with regular version check (bsc#1206798)");

  script_tag(name:"affected", value:"'busybox, busybox-links' package(s) on SUSE Linux Enterprise Server 15-SP5, SUSE Linux Enterprise Server 15-SP6, SUSE Linux Enterprise Server for SAP Applications 15-SP5.");

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

if(release == "SLES15.0SP5") {

  if(!isnull(res = isrpmvuln(pkg:"busybox", rpm:"busybox~1.37.0~150500.10.11.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-static", rpm:"busybox-static~1.37.0~150500.10.11.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES15.0SP6") {

  if(!isnull(res = isrpmvuln(pkg:"busybox", rpm:"busybox~1.37.0~150500.10.11.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-static", rpm:"busybox-static~1.37.0~150500.10.11.1", rls:"SLES15.0SP6"))) {
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
