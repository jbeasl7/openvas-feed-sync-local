# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2018.3330.1");
  script_cve_id("CVE-2017-9611", "CVE-2018-15910", "CVE-2018-16509", "CVE-2018-16511", "CVE-2018-16513", "CVE-2018-16540", "CVE-2018-16541", "CVE-2018-16542");
  script_tag(name:"creation_date", value:"2021-06-09 14:57:35 +0000 (Wed, 09 Jun 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-10-30 18:31:39 +0000 (Tue, 30 Oct 2018)");

  script_name("SUSE: Security Advisory (SUSE-SU-2018:3330-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP3|SLES11\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2018:3330-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2018/suse-su-20183330-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1050893");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1106173");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1107410");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1107412");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1107413");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1107420");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1107421");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1107426");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2018-October/004767.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ghostscript-library' package(s) announced via the SUSE-SU-2018:3330-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for ghostscript-library fixes the following issues:

- CVE-2018-16511: A type confusion in 'ztype' could be used by remote attackers able to supply crafted PostScript to crash the interpreter or possibly have unspecified other impact. (bsc#1107426)
- CVE-2018-16540: Attackers able to supply crafted PostScript files to the builtin PDF14 converter could use a use-after-free in copydevice handling to crash the interpreter or possibly have unspecified other impact. (bsc#1107420)
- CVE-2018-16541: Attackers able to supply crafted PostScript files could use incorrect free logic in pagedevice replacement to crash the interpreter. (bsc#1107421)
- CVE-2018-16542: Attackers able to supply crafted PostScript files could use insufficient interpreter stack-size checking during error handling to crash the interpreter. (bsc#1107413)
- CVE-2018-16509: Incorrect 'restoration of privilege' checking during handling of /invalidaccess exceptions could be used by attackers able to supply crafted PostScript to execute code using the 'pipe' instruction. (bsc#1107410
- CVE-2018-16513: Attackers able to supply crafted PostScript files could use a type confusion in the setcolor function to crash the interpreter or possibly have unspecified other impact. (bsc#1107412)
- CVE-2018-15910: Attackers able to supply crafted PostScript files could use a type confusion in the LockDistillerParams parameter to crash the interpreter or execute code. (bsc#1106173)
- CVE-2017-9611: The Ins_MIRP function allowed remote attackers to cause a denial of service (heap-based buffer over-read and application crash) or possibly have unspecified other impact via a crafted document. (bsc#1050893)");

  script_tag(name:"affected", value:"'ghostscript-library' package(s) on SUSE Linux Enterprise Server 11-SP3, SUSE Linux Enterprise Server 11-SP4, SUSE Linux Enterprise Server for SAP Applications 11-SP4.");

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

if(release == "SLES11.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"ghostscript-fonts-other", rpm:"ghostscript-fonts-other~8.62~32.47.13.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghostscript-fonts-rus", rpm:"ghostscript-fonts-rus~8.62~32.47.13.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghostscript-fonts-std", rpm:"ghostscript-fonts-std~8.62~32.47.13.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghostscript-library", rpm:"ghostscript-library~8.62~32.47.13.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghostscript-omni", rpm:"ghostscript-omni~8.62~32.47.13.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghostscript-x11", rpm:"ghostscript-x11~8.62~32.47.13.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgimpprint", rpm:"libgimpprint~4.2.7~32.47.13.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES11.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"ghostscript-fonts-other", rpm:"ghostscript-fonts-other~8.62~32.47.13.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghostscript-fonts-rus", rpm:"ghostscript-fonts-rus~8.62~32.47.13.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghostscript-fonts-std", rpm:"ghostscript-fonts-std~8.62~32.47.13.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghostscript-library", rpm:"ghostscript-library~8.62~32.47.13.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghostscript-omni", rpm:"ghostscript-omni~8.62~32.47.13.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghostscript-x11", rpm:"ghostscript-x11~8.62~32.47.13.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgimpprint", rpm:"libgimpprint~4.2.7~32.47.13.1", rls:"SLES11.0SP4"))) {
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
