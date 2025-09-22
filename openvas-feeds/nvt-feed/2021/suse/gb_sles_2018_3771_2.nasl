# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2018.3771.2");
  script_cve_id("CVE-2018-19131", "CVE-2018-19132");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-12-11 20:54:45 +0000 (Tue, 11 Dec 2018)");

  script_name("SUSE: Security Advisory (SUSE-SU-2018:3771-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2018:3771-2");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2018/suse-su-20183771-2.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1082318");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1112066");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1112695");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1113668");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1113669");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2018-December/004928.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'squid' package(s) announced via the SUSE-SU-2018:3771-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for squid fixes the following issues:

Security issues fixed:

- CVE-2018-19131: Fixed Cross-Site-Scripting vulnerability in the TLS error handling (bsc#1113668).
- CVE-2018-19132: Fixed small memory leak in processing of SNMP packets (bsc#1113669).

Non-security issues fixed:

- Create runtime directories needed when SMP mode is enabled (bsc#1112695, bsc#1112066).
- Install license correctly (bsc#1082318).");

  script_tag(name:"affected", value:"'squid' package(s) on SUSE Linux Enterprise Server 12-SP4, SUSE Linux Enterprise Server for SAP Applications 12-SP4.");

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

if(release == "SLES12.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"squid", rpm:"squid~3.5.21~26.12.1", rls:"SLES12.0SP4"))) {
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
