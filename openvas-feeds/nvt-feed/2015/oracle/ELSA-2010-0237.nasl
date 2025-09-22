# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.122370");
  script_cve_id("CVE-2006-7176", "CVE-2009-4565");
  script_tag(name:"creation_date", value:"2015-10-06 11:17:41 +0000 (Tue, 06 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Oracle: Security Advisory (ELSA-2010-0237)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux5");

  script_xref(name:"Advisory-ID", value:"ELSA-2010-0237");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2010-0237.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'sendmail' package(s) announced via the ELSA-2010-0237 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[8.13.8-8]

- rpm attributes S,5,T not recorded for statistics file

[8.13.8-7]
- fix specfile for passing rpm -V test (#555277)

[8.13.8-6.el5]
- fix verification of SSL certificate with NUL in name (#553618, CVE-2009-4565)
- do not accept localhost.localdomain as valid address from smtp (#449391)
- skip colon separator when parsing service name in ServiceSwitchFile (#512871)
- exit with non-zero error code when free space is low (#299951)
- fix -qG description in man page (#250552)
- fix comments in sendmail.mc to use correct certs path (#244012)
- add MTA to provides (#494408)
- fix %dist macro use (#440616)
- compile with -fno-strict-aliasing
- skip t-sem test as it doesn't allow parallel testing");

  script_tag(name:"affected", value:"'sendmail' package(s) on Oracle Linux 5.");

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

  if(!isnull(res = isrpmvuln(pkg:"sendmail", rpm:"sendmail~8.13.8~8.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sendmail-cf", rpm:"sendmail-cf~8.13.8~8.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sendmail-devel", rpm:"sendmail-devel~8.13.8~8.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sendmail-doc", rpm:"sendmail-doc~8.13.8~8.el5", rls:"OracleLinux5"))) {
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
