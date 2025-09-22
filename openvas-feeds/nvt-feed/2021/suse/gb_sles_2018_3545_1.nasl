# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2018.3545.1");
  script_cve_id("CVE-2016-10165", "CVE-2018-16435");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-02-09 15:05:10 +0000 (Thu, 09 Feb 2017)");

  script_name("SUSE: Security Advisory (SUSE-SU-2018:3545-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2018:3545-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2018/suse-su-20183545-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1021364");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1026649");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1026650");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1108813");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2018-October/004806.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'lcms2' package(s) announced via the SUSE-SU-2018:3545-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for lcms2 fixes the following security issues:

- CVE-2016-10165: The Type_MLU_Read function allowed remote attackers to obtain
 sensitive information or cause a denial of service via an image with a crafted
 ICC profile, which triggered an out-of-bounds heap read (bsc#1021364).
- CVE-2018-16435: A integer overflow was fixed in the AllocateDataSet
 function in cmscgats.c, that could lead to a heap-based buffer overflow
 in the SetData function via a crafted file in the second argument to
 cmsIT8LoadFromFile. (bsc#1108813)
- Ensure that LUT stages match channel count (bsc#1026649).
- sanitize input and output channels on MPE profiles (bsc#1026650).");

  script_tag(name:"affected", value:"'lcms2' package(s) on SUSE Linux Enterprise Desktop 12-SP3, SUSE Linux Enterprise Server 12-SP3, SUSE Linux Enterprise Server for SAP Applications 12-SP3.");

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

  if(!isnull(res = isrpmvuln(pkg:"lcms2", rpm:"lcms2~2.7~9.7.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"liblcms2-2", rpm:"liblcms2-2~2.7~9.7.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"liblcms2-2-32bit", rpm:"liblcms2-2-32bit~2.7~9.7.1", rls:"SLES12.0SP3"))) {
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
