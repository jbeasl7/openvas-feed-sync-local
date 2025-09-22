# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.123505");
  script_cve_id("CVE-2013-1739", "CVE-2013-1741", "CVE-2013-5605", "CVE-2013-5606", "CVE-2013-5607");
  script_tag(name:"creation_date", value:"2015-10-06 11:04:47 +0000 (Tue, 06 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Oracle: Security Advisory (ELSA-2013-1791)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux5");

  script_xref(name:"Advisory-ID", value:"ELSA-2013-1791");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2013-1791.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'nspr, nss' package(s) announced via the ELSA-2013-1791 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"nspr
[4.10.2-2]
- Fix changelog comments
- Resolves: rhbz#1032466 - CVE-2013-5605 CVE-2013-5606 CVE-2013-1741 nss: various flaws [rhel-5.10]

[4.10.2-1]
- Update to nspr-4.10.2
- Remove an unused patch
- Resolves: rhbz#1032466 - CVE-2013-5605 CVE-2013-5606 CVE-2013-1741 nss: various flaws [rhel-5.10]

[4.10.0-2]
- Retagging to fix an inconsistency in the release tags
- Resolves: rhbz#1002641 - Rebase RHEL 5 to NSPR 4.10 (for FF 24.x)

[4.9.5-1]
- Rebase to nspr-4.10.0
- Resolves: rhbz#1002641 - Rebase RHEL 5 to NSPR 4.10 (for FF 24.x)

nss
[3.15.3-3]
- remove unnecessary and problematic template-removal patch
 which was added as part of the 3.15.1 rebase
- bump release number

[3.15.3-1]
- Update to nss-3.15.3
- Remove unused patch
- Resolves: rhbz#1032466 - CVE-2013-5605 CVE-2013-5606 CVE-2013-1741 nss: various flaws [rhel-5.10]

[3.15.1-2]
- Remove unused patches
- Resolves: rhbz#1033478 - Rebase RHEL 5 to NSS 3.15.1 (for FF 24.x)

[3.15.1-1]
- Rebase to nss-3.15.1
- Resolves: rhbz#1033478 - Rebase RHEL 5 to NSS 3.15.1 (for FF 24.x)
- Resolves: rhbz#1033499 - [Regression] NSS no longer trusts MD5 certificates
- Split %check section tests in two: freebl/softoken and rest of nss tests
- Adjust various patches and spec file steps on account of the rebase
- Add various patches and remove obsoleted ones on account of the rebase
- Renumber patches so freeb/softoken ones match the corresponding ones in rhel-6 nss-softokn");

  script_tag(name:"affected", value:"'nspr, nss' package(s) on Oracle Linux 5.");

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

  if(!isnull(res = isrpmvuln(pkg:"nspr", rpm:"nspr~4.10.2~2.el5_10", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nspr-devel", rpm:"nspr-devel~4.10.2~2.el5_10", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nss", rpm:"nss~3.15.3~3.el5_10", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nss-devel", rpm:"nss-devel~3.15.3~3.el5_10", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nss-pkcs11-devel", rpm:"nss-pkcs11-devel~3.15.3~3.el5_10", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nss-tools", rpm:"nss-tools~3.15.3~3.el5_10", rls:"OracleLinux5"))) {
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
