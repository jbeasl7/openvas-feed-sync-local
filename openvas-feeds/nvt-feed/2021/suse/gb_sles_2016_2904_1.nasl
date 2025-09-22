# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2016.2904.1");
  script_cve_id("CVE-2014-9680", "CVE-2016-7032", "CVE-2016-7076");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-07-09 14:21:14 +0000 (Mon, 09 Jul 2018)");

  script_name("SUSE: Security Advisory (SUSE-SU-2016:2904-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP1)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2016:2904-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2016/suse-su-20162904-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1007501");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1007766");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/899252");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/917806");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/979531");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2016-November/002420.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'sudo' package(s) announced via the SUSE-SU-2016:2904-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for sudo fixes the following security issues:

- Fix two security vulnerabilities that allowed users to bypass sudo's NOEXEC functionality:
 * noexec bypass via system() and popen() [CVE-2016-7032, bsc#1007766]
 * noexec bypass via wordexp() [CVE-2016-7076, bsc#1007501]
- Fix unsafe handling of TZ environment variable. [CVE-2014-9680, bsc#917806]

Additionally, these non-security fixes are included in the update:

- Fix 'ignoring time stamp from the future' message after each boot with !tty_tickets. [bsc#899252]
- Enable support for SASL-based authentication. [bsc#979531]");

  script_tag(name:"affected", value:"'sudo' package(s) on SUSE Linux Enterprise Desktop 12-SP1, SUSE Linux Enterprise Server 12-SP1, SUSE Linux Enterprise Server for SAP Applications 12-SP1.");

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

  if(!isnull(res = isrpmvuln(pkg:"sudo", rpm:"sudo~1.8.10p3~2.6.1", rls:"SLES12.0SP1"))) {
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
