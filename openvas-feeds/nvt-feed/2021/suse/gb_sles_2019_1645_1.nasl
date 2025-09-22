# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2019.1645.1");
  script_cve_id("CVE-2017-2579", "CVE-2017-2580", "CVE-2018-8975");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-09-19 17:53:52 +0000 (Wed, 19 Sep 2018)");

  script_name("SUSE: Security Advisory (SUSE-SU-2019:1645-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP3|SLES12\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2019:1645-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2019/suse-su-20191645-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1024288");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1024291");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1086777");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1136936");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2019-June/005619.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'netpbm' package(s) announced via the SUSE-SU-2019:1645-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for netpbm fixes the following issues:

Security issues fixed:

- CVE-2018-8975: The pm_mallocarray2 function allowed remote attackers to cause
 a denial of service (heap-based buffer over-read) via a crafted image file (bsc#1086777).
- CVE-2017-2579: Fixed out-of-bounds read in expandCodeOntoStack() (bsc#1024288).
- CVE-2017-2580: Fixed out-of-bounds write of heap data in addPixelToRaster() function (bsc#1024291).

- create netpbm-vulnerable subpackage and move pstopnm there (bsc#1136936)");

  script_tag(name:"affected", value:"'netpbm' package(s) on SUSE Linux Enterprise Desktop 12-SP3, SUSE Linux Enterprise Desktop 12-SP4, SUSE Linux Enterprise Server 12-SP3, SUSE Linux Enterprise Server 12-SP4, SUSE Linux Enterprise Server for SAP Applications 12-SP3, SUSE Linux Enterprise Server for SAP Applications 12-SP4.");

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

if(release == "SLES12.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"libnetpbm11", rpm:"libnetpbm11~10.66.3~8.7.2", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnetpbm11-32bit", rpm:"libnetpbm11-32bit~10.66.3~8.7.2", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netpbm", rpm:"netpbm~10.66.3~8.7.2", rls:"SLES12.0SP3"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"libnetpbm11", rpm:"libnetpbm11~10.66.3~8.7.2", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnetpbm11-32bit", rpm:"libnetpbm11-32bit~10.66.3~8.7.2", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netpbm", rpm:"netpbm~10.66.3~8.7.2", rls:"SLES12.0SP4"))) {
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
