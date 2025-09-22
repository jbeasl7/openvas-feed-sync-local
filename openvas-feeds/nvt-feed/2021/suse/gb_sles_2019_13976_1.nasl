# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2019.13976.1");
  script_cve_id("CVE-2018-19636", "CVE-2018-19638", "CVE-2018-19639", "CVE-2018-19640");
  script_tag(name:"creation_date", value:"2021-06-09 14:57:30 +0000 (Wed, 09 Jun 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-03-05 21:48:48 +0000 (Tue, 05 Mar 2019)");

  script_name("SUSE: Security Advisory (SUSE-SU-2019:13976-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2019:13976-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2019/suse-su-201913976-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1117751");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1118460");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1118462");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1118463");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2019-March/005187.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'supportutils' package(s) announced via the SUSE-SU-2019:13976-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for supportutils fixes the following issues:

Security vulnerabilities fixed:

- CVE-2018-19636: Local root exploit via inclusion of attacker controlled shell script (bsc#1117751)
- CVE-2018-19640: Users can kill arbitrary processes (bsc#1118463)
- CVE-2018-19638: User can overwrite arbitrary log files in support tar (bsc#1118460)
- CVE-2018-19639: Code execution if run with -v (bsc#1118462)");

  script_tag(name:"affected", value:"'supportutils' package(s) on SUSE Linux Enterprise Server 11-SP4, SUSE Linux Enterprise Server for SAP Applications 11-SP4.");

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

if(release == "SLES11.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"supportutils", rpm:"supportutils~1.20~122.9.1", rls:"SLES11.0SP4"))) {
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
