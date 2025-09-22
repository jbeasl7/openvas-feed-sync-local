# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.123756");
  script_cve_id("CVE-2007-4772", "CVE-2007-6067");
  script_tag(name:"creation_date", value:"2015-10-06 11:08:07 +0000 (Tue, 06 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:C");

  script_name("Oracle: Security Advisory (ELSA-2013-0122)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux5");

  script_xref(name:"Advisory-ID", value:"ELSA-2013-0122");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2013-0122.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'tcl' package(s) announced via the ELSA-2013-0122 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[8.4.13-6]
- Fixed infinite loop in regex NFA optimization code
 Resolves: CVE-2007-4772
- Fixed O(N^2) compile time (and huge memory requirements) for some regexps
 Resolves: CVE-2007-6067

[8.4.13-5]
- Threaded / nonthreaded versions of tcl are now switchable through alternatives
 Resolves: rhbz#478961");

  script_tag(name:"affected", value:"'tcl' package(s) on Oracle Linux 5.");

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

if(release == "OracleLinux5") {

  if(!isnull(res = isrpmvuln(pkg:"tcl", rpm:"tcl~8.4.13~6.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tcl-devel", rpm:"tcl-devel~8.4.13~6.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tcl-html", rpm:"tcl-html~8.4.13~6.el5", rls:"OracleLinux5"))) {
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
