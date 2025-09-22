# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2017.0123.1");
  script_cve_id("CVE-2016-1246", "CVE-2016-1249", "CVE-2016-1251");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-12-01 19:25:33 +0000 (Thu, 01 Dec 2016)");

  script_name("SUSE: Security Advisory (SUSE-SU-2017:0123-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP1|SLES12\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2017:0123-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2017/suse-su-20170123-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1002626");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1010457");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1012546");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2017-January/002560.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'perl-DBD-mysql' package(s) announced via the SUSE-SU-2017:0123-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for perl-DBD-mysql fixes the following issues:

- CVE-2016-1251: A use-after-free when used with mysql_server_prepare=1 (bsc#1012546).
- CVE-2016-1246: Buffer overflow allowed context-dependent attackers to cause a denial of service (crash) via vectors related to an error message (bsc#1002626).
- CVE-2016-1249: Out-of-bounds read when using server-side prepared statement support (bsc#1010457).");

  script_tag(name:"affected", value:"'perl-DBD-mysql' package(s) on SUSE Linux Enterprise Server 12-SP1, SUSE Linux Enterprise Server 12-SP2, SUSE Linux Enterprise Server for Raspberry Pi 12-SP2, SUSE Linux Enterprise Server for SAP Applications 12-SP1, SUSE Linux Enterprise Server for SAP Applications 12-SP2.");

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

if(release == "SLES12.0SP1") {

  if(!isnull(res = isrpmvuln(pkg:"perl-DBD-mysql", rpm:"perl-DBD-mysql~4.021~11.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES12.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"perl-DBD-mysql", rpm:"perl-DBD-mysql~4.021~11.1", rls:"SLES12.0SP2"))) {
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
