# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.123174");
  script_cve_id("CVE-2014-9273");
  script_tag(name:"creation_date", value:"2015-10-06 11:00:19 +0000 (Tue, 06 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Oracle: Security Advisory (ELSA-2015-0301)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux7");

  script_xref(name:"Advisory-ID", value:"ELSA-2015-0301");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2015-0301.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'hivex' package(s) announced via the ELSA-2015-0301 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[1.3.10-5.7]
- Fix: 'Argument list too long' when using virt-v2v on Windows guest
 with French copy of Citrix installed
 related: rhbz#1145056

[1.3.10-5.6]
- Fix: typo in man page
 resolves: rhbz#1099286

[1.3.10-5.4]
- Fix: hivex missing checks for small/truncated files
 resolves: rhbz#1158992

[1.3.10-5.3]
- Fix: hivexml generates 'Argument list too long' error.
 resolves: rhbz#1145056

[1.3.10-5.2]
- Resolves: rhbz#1125544

[1.3.10-5.1]
- Rebase to hivex 1.3.10.
 resolves: rhbz#1023978");

  script_tag(name:"affected", value:"'hivex' package(s) on Oracle Linux 7.");

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

if(release == "OracleLinux7") {

  if(!isnull(res = isrpmvuln(pkg:"hivex", rpm:"hivex~1.3.10~5.7.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"hivex-devel", rpm:"hivex-devel~1.3.10~5.7.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocaml-hivex", rpm:"ocaml-hivex~1.3.10~5.7.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocaml-hivex-devel", rpm:"ocaml-hivex-devel~1.3.10~5.7.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-hivex", rpm:"perl-hivex~1.3.10~5.7.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-hivex", rpm:"python-hivex~1.3.10~5.7.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby-hivex", rpm:"ruby-hivex~1.3.10~5.7.el7", rls:"OracleLinux7"))) {
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
