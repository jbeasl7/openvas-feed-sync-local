# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2019.3067.1");
  script_cve_id("CVE-2019-12523", "CVE-2019-12526", "CVE-2019-13345", "CVE-2019-18676", "CVE-2019-18677", "CVE-2019-18678", "CVE-2019-18679");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-12-16 13:52:06 +0000 (Mon, 16 Dec 2019)");

  script_name("SUSE: Security Advisory (SUSE-SU-2019:3067-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2019:3067-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2019/suse-su-20193067-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1140738");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1156323");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1156324");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1156326");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1156328");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1156329");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2019-November/006179.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'squid' package(s) announced via the SUSE-SU-2019:3067-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for squid to version 4.9 fixes the following issues:

Security issues fixed:

- CVE-2019-13345: Fixed multiple cross-site scripting vulnerabilities in cachemgr.cgi (bsc#1140738).
- CVE-2019-12526: Fixed potential remote code execution during URN processing (bsc#1156326).
- CVE-2019-12523,CVE-2019-18676: Fixed multiple improper validations in URI processing (bsc#1156329).
- CVE-2019-18677: Fixed Cross-Site Request Forgery in HTTP Request processing (bsc#1156328).
- CVE-2019-18678: Fixed incorrect message parsing which could have led to HTTP request splitting issue (bsc#1156323).
- CVE-2019-18679: Fixed information disclosure when processing HTTP Digest Authentication (bsc#1156324).

Other issues addressesd:

 * Fixed DNS failures when peer name was configured with any upper case characters
 * Fixed several rock cache_dir corruption issues");

  script_tag(name:"affected", value:"'squid' package(s) on SUSE Linux Enterprise Server 12-SP5, SUSE Linux Enterprise Server for SAP Applications 12-SP5.");

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

if(release == "SLES12.0SP5") {

  if(!isnull(res = isrpmvuln(pkg:"squid", rpm:"squid~4.9~4.3.2", rls:"SLES12.0SP5"))) {
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
