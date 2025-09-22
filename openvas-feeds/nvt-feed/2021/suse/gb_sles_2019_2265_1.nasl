# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2019.2265.1");
  script_cve_id("CVE-2018-20532", "CVE-2018-20533", "CVE-2018-20534");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-01-06 17:21:39 +0000 (Sun, 06 Jan 2019)");

  script_name("SUSE: Security Advisory (SUSE-SU-2019:2265-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP2|SLES12\.0SP3|SLES12\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2019:2265-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2019/suse-su-20192265-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1049825");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1109893");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1110542");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1111319");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1112911");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1113296");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1116995");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1120629");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1120630");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1120631");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1127155");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1131823");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1134226");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1137977");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1140039");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1145521");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libsolv, libzypp, zypper' package(s) announced via the SUSE-SU-2019:2265-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for libsolv, libzypp and zypper fixes the following issues:

libsolv was updated to version 0.6.36 and fixes the following issues:

Security issues fixed:

- CVE-2018-20532: Fixed a NULL pointer dereference in testcase_read() (bsc#1120629).
- CVE-2018-20533: Fixed a NULL pointer dereference in testcase_str2dep_complex() (bsc#1120630).
- CVE-2018-20534: Fixed a NULL pointer dereference in pool_whatprovides() (bsc#1120631).

Non-security issues fixed:

- Made cleandeps jobs on patterns work (bsc#1137977).
- Fixed an issue multiversion packages that obsolete their own name (bsc#1127155).
- Keep consistent package name if there are multiple alternatives (bsc#1131823).

Fixes for libzypp:

- Fixes a bug where locking the kernel was not possible (bsc#1113296)
- Fixes a file descriptor leak (bsc#1116995)
- Will now run file conflict check on dry-run (best with download-only) (bsc#1140039)

Fixes for zypper:

- Fixes a bug where the wrong exit code was set when refreshing repos if --root was used (bsc#1134226)
- Improved the displaying of locks (bsc#1112911)
- Fixes an issue where `https` repository urls caused an error prompt to appear twice (bsc#1110542)
- zypper will now always warn when no repositories are defined (bsc#1109893)
- Fixes bash completion option detection (bsc#1049825)");

  script_tag(name:"affected", value:"'libsolv, libzypp, zypper' package(s) on SUSE Linux Enterprise Desktop 12-SP4, SUSE Linux Enterprise Server 12-SP2, SUSE Linux Enterprise Server 12-SP3, SUSE Linux Enterprise Server 12-SP4, SUSE Linux Enterprise Server for SAP Applications 12-SP2, SUSE Linux Enterprise Server for SAP Applications 12-SP3, SUSE Linux Enterprise Server for SAP Applications 12-SP4.");

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

if(release == "SLES12.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"libsolv-tools", rpm:"libsolv-tools~0.6.36~2.27.19.8", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libzypp", rpm:"libzypp~16.20.2~27.60.4", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-solv", rpm:"perl-solv~0.6.36~2.27.19.8", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-solv", rpm:"python-solv~0.6.36~2.27.19.8", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zypper", rpm:"zypper~1.13.54~18.40.2", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zypper-log", rpm:"zypper-log~1.13.54~18.40.2", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES12.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"libsolv-tools", rpm:"libsolv-tools~0.6.36~2.27.19.8", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libzypp", rpm:"libzypp~16.20.2~27.60.4", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-solv", rpm:"perl-solv~0.6.36~2.27.19.8", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-solv", rpm:"python-solv~0.6.36~2.27.19.8", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zypper", rpm:"zypper~1.13.54~18.40.2", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zypper-log", rpm:"zypper-log~1.13.54~18.40.2", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES12.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"libsolv-tools", rpm:"libsolv-tools~0.6.36~2.27.19.8", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libzypp", rpm:"libzypp~16.20.2~27.60.4", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-solv", rpm:"perl-solv~0.6.36~2.27.19.8", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-solv", rpm:"python-solv~0.6.36~2.27.19.8", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zypper", rpm:"zypper~1.13.54~18.40.2", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zypper-log", rpm:"zypper-log~1.13.54~18.40.2", rls:"SLES12.0SP4"))) {
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
