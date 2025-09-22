# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2020.0545.1");
  script_cve_id("CVE-2020-8013");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"1.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:N/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-03-04 15:21:21 +0000 (Wed, 04 Mar 2020)");

  script_name("SUSE: Security Advisory (SUSE-SU-2020:0545-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP2|SLES12\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2020:0545-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2020/suse-su-20200545-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1123886");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1160594");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1160764");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1161779");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1163922");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2020-February/006557.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'permissions' package(s) announced via the SUSE-SU-2020:0545-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for permissions fixes the following issues:

Security issues fixed:

- CVE-2020-8013: Fixed an issue where chkstat set unintended setuid/capabilities for mrsh and wodim (bsc#1163922).

Non-security issues fixed:

- Fixed a regression where chkstat broke when /proc was not available (bsc#1160764, bsc#1160594).
- Fixed capability handling when doing multiple permission changes at once (bsc#1161779).");

  script_tag(name:"affected", value:"'permissions' package(s) on SUSE Linux Enterprise Server 12-SP2, SUSE Linux Enterprise Server 12-SP3, SUSE Linux Enterprise Server for SAP Applications 12-SP2, SUSE Linux Enterprise Server for SAP Applications 12-SP3.");

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

  if(!isnull(res = isrpmvuln(pkg:"permissions", rpm:"permissions~2015.09.28.1626~17.27.1", rls:"SLES12.0SP2"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"permissions", rpm:"permissions~2015.09.28.1626~17.27.1", rls:"SLES12.0SP3"))) {
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
