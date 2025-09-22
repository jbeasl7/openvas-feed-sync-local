# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2017.1989.1");
  script_cve_id("CVE-2016-5824", "CVE-2016-5827", "CVE-2016-9584");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-01-20 17:26:08 +0000 (Fri, 20 Jan 2017)");

  script_name("SUSE: Security Advisory (SUSE-SU-2017:1989-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP2|SLES12\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2017:1989-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2017/suse-su-20171989-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1015964");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1044995");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/986631");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/986639");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2017-July/003072.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libical' package(s) announced via the SUSE-SU-2017:1989-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for libical fixes the following issues:

Security issues fixed:
- CVE-2016-5824: libical 1.0 allows remote attackers to cause a denial of service (use-after-free)
 via a crafted ics file. (bsc#986639)
- CVE-2016-5827: The icaltime_from_string function in libical 0.47 and 1.0 allows remote attackers
 to cause a denial of service (out-of-bounds heap read) via a crafted string to the
 icalparser_parse_string function. (bsc#986631)
- CVE-2016-9584: libical allows remote attackers to cause a denial of service (use-after-free) and
 possibly read heap memory via a crafted ics file. (bsc#1015964)

Bug fixes:
- libical crashes while parsing timezones (bsc#1044995)");

  script_tag(name:"affected", value:"'libical' package(s) on SUSE Linux Enterprise Desktop 12-SP2, SUSE Linux Enterprise Desktop 12-SP3, SUSE Linux Enterprise Server 12-SP2, SUSE Linux Enterprise Server 12-SP3, SUSE Linux Enterprise Server for Raspberry Pi 12-SP2, SUSE Linux Enterprise Server for SAP Applications 12-SP2, SUSE Linux Enterprise Server for SAP Applications 12-SP3.");

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

  if(!isnull(res = isrpmvuln(pkg:"libical1", rpm:"libical1~1.0.1~16.3.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libical1-32bit", rpm:"libical1-32bit~1.0.1~16.3.1", rls:"SLES12.0SP2"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"libical1", rpm:"libical1~1.0.1~16.3.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libical1-32bit", rpm:"libical1-32bit~1.0.1~16.3.1", rls:"SLES12.0SP3"))) {
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
