# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.123330");
  script_cve_id("CVE-2014-1492");
  script_tag(name:"creation_date", value:"2015-10-06 11:02:21 +0000 (Tue, 06 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_name("Oracle: Security Advisory (ELSA-2014-1073)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux7");

  script_xref(name:"Advisory-ID", value:"ELSA-2014-1073");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2014-1073.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'nss, nss-softokn, nss-util' package(s) announced via the ELSA-2014-1073 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"nss
[3.16.2-2.0.1.el7_0]
- Added nss-vendor.patch to change vendor

[3.16.2-2]
- Restore missing options descriptions fix for certutil manpage
- Document certutil options --dump-ext-val, --extGeneric, and --extSAN
- Related: Bug 1124659 - Rebase RHEL 7 to at least NSS 3.16.1

[3.16.2-1]
- Rebase to nss-3.16.2
- Resolves: Bug 1124659 - Rebase RHEL 7 to at least NSS 3.16.1 (FF 31)
- Fix test failure detection in the %check section
- Move removal of unwanted source directories to the end of the %prep section
- Update various patches on account of the rebase
- Remove unused patches rendered obsolete by the rebase
- Fix libssl and test patches that disable ssl2 support
- Replace expired PayPal test certificate that breaks the build

nss-softokn
[3.16.2-1]
- Update to nss-3.16.2
- Resolves: Bug 1124659 - Rebase RHEL 7.1 to at least NSS-SOFTOKN 3.16.1 (FF 31)

nss-util
[3.16.2-1]
- Update to nss-3.16.2
- Resolves: Bug 1124659 - Rebase RHEL-7.0 to at least NSS 3.16.1 (FF 31)");

  script_tag(name:"affected", value:"'nss, nss-softokn, nss-util' package(s) on Oracle Linux 7.");

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

  if(!isnull(res = isrpmvuln(pkg:"nss", rpm:"nss~3.16.2~2.0.1.el7_0", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nss-devel", rpm:"nss-devel~3.16.2~2.0.1.el7_0", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nss-pkcs11-devel", rpm:"nss-pkcs11-devel~3.16.2~2.0.1.el7_0", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nss-softokn", rpm:"nss-softokn~3.16.2~1.el7_0", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nss-softokn-devel", rpm:"nss-softokn-devel~3.16.2~1.el7_0", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nss-softokn-freebl", rpm:"nss-softokn-freebl~3.16.2~1.el7_0", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nss-softokn-freebl-devel", rpm:"nss-softokn-freebl-devel~3.16.2~1.el7_0", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nss-sysinit", rpm:"nss-sysinit~3.16.2~2.0.1.el7_0", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nss-tools", rpm:"nss-tools~3.16.2~2.0.1.el7_0", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nss-util", rpm:"nss-util~3.16.2~1.el7_0", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nss-util-devel", rpm:"nss-util-devel~3.16.2~1.el7_0", rls:"OracleLinux7"))) {
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
