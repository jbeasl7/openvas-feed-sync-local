# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.122646");
  script_cve_id("CVE-2007-5116");
  script_tag(name:"creation_date", value:"2015-10-08 11:50:11 +0000 (Thu, 08 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Oracle: Security Advisory (ELSA-2007-0966)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=(OracleLinux3|OracleLinux4|OracleLinux5)");

  script_xref(name:"Advisory-ID", value:"ELSA-2007-0966");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2007-0966.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'perl' package(s) announced via the ELSA-2007-0966 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[5.8.5-36.el4_5.2.0.1]
 - Added patch perl-5.8.5-OEL-mock-build.patch to disable test
 lib/Net/t/hostname.t, so that mock build succeeds

 [5.8.5-36.el4.2]
 - Resolves: bug#323791
 - fix previous patch

 [5.8.5-36.el4.1]
 - Resolves: bug#323791
 - fix regular expression UTF parsing errors");

  script_tag(name:"affected", value:"'perl' package(s) on Oracle Linux 3, Oracle Linux 4, Oracle Linux 5.");

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

if(release == "OracleLinux3") {

  if(!isnull(res = isrpmvuln(pkg:"perl", rpm:"perl~5.8.0~97.EL3.0.1", rls:"OracleLinux3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-CGI", rpm:"perl-CGI~2.89~97.EL3.0.1", rls:"OracleLinux3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-CPAN", rpm:"perl-CPAN~1.61~97.EL3.0.1", rls:"OracleLinux3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-DB_File", rpm:"perl-DB_File~1.806~97.EL3.0.1", rls:"OracleLinux3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-suidperl", rpm:"perl-suidperl~5.8.0~97.EL3.0.1", rls:"OracleLinux3"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "OracleLinux4") {

  if(!isnull(res = isrpmvuln(pkg:"perl", rpm:"perl~5.8.5~36.el4_5.2.0.1", rls:"OracleLinux4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-suidperl", rpm:"perl-suidperl~5.8.5~36.el4_5.2.0.1", rls:"OracleLinux4"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "OracleLinux5") {

  if(!isnull(res = isrpmvuln(pkg:"perl", rpm:"perl~5.8.8~10.0.1.el5_0.2", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-suidperl", rpm:"perl-suidperl~5.8.8~10.0.1.el5_0.2", rls:"OracleLinux5"))) {
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
