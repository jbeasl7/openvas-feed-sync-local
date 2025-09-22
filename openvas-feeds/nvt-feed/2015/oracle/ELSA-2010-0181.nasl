# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.122373");
  script_cve_id("CVE-2008-3279");
  script_tag(name:"creation_date", value:"2015-10-06 11:17:43 +0000 (Tue, 06 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");

  script_name("Oracle: Security Advisory (ELSA-2010-0181)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux5");

  script_xref(name:"Advisory-ID", value:"ELSA-2010-0181");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2010-0181.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'brltty' package(s) announced via the ELSA-2010-0181 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[3.7.2-4]
- use rpm macros more consistently
- add manual page for brltty.conf
- add more documentation
- install the default brltty-pm.conf to docdir only
- Resolves: #530554
- silence the postinstall scriptlet
- Resolves: #529163

[3.7.2-3]
- escape rpm macros in the rpm change log
- remove bogus rpath from libbrlttybba.so (CVE-2008-3279, #457942)
- add dependencies to bind the subpackages from one build together

[3.7.2-2]
- fix building with newer kernel-headers (#456247)
- do not strip debug info during install (#500545)
- Resolves: rhbz #456247 #500545");

  script_tag(name:"affected", value:"'brltty' package(s) on Oracle Linux 5.");

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

  if(!isnull(res = isrpmvuln(pkg:"brlapi", rpm:"brlapi~0.4.1~4.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"brlapi-devel", rpm:"brlapi-devel~0.4.1~4.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"brltty", rpm:"brltty~3.7.2~4.el5", rls:"OracleLinux5"))) {
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
