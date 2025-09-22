# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2013.0163");
  script_cve_id("CVE-2012-3251", "CVE-2012-3522");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-02-02T05:06:08+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:08 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_name("Mageia: Security Advisory (MGASA-2013-0163)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA2");

  script_xref(name:"Advisory-ID", value:"MGASA-2013-0163");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2013-0163.html");
  script_xref(name:"URL", value:"http://lists.fedoraproject.org/pipermail/package-announce/2013-May/105247.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'php-geshi' package(s) announced via the MGASA-2013-0163 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A directory traversal and information disclosure (local file inclusion) flaws
were found in the cssgen contrib module (application to generate custom CSS
files) of GeSHi, a generic syntax highlighter, performed sanitization of
'geshi-path' and 'geshi-lang-path' HTTP GET / POST variables. A remote
attacker could provide a specially-crafted URL that, when visited could lead
to local file system traversal or, potentially, ability to read content of
any local file, accessible with the privileges of the user running the
webserver (CVE-2012-3251).

A cross-site scripting (XSS) flaw was found in the way 'langwiz' example
script of GeSHi, a generic syntax highlighter, performed sanitization of
certain HTTP GET / POST request variables (prior dumping their content). A
remote attacker could provide a specially-crafted URL that, when visited
would lead to arbitrary HTML or web script execution (CVE-2012-3522).");

  script_tag(name:"affected", value:"'php-geshi' package(s) on Mageia 2.");

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

if(release == "MAGEIA2") {

  if(!isnull(res = isrpmvuln(pkg:"php-geshi", rpm:"php-geshi~1.0.8.11~1.mga2", rls:"MAGEIA2"))) {
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
