# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.122725");
  script_cve_id("CVE-2015-7181", "CVE-2015-7182", "CVE-2015-7183");
  script_tag(name:"creation_date", value:"2015-11-08 11:05:16 +0000 (Sun, 08 Nov 2015)");
  script_version("2025-01-23T05:37:39+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:39 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-11-04 01:29:00 +0000 (Sat, 04 Nov 2017)");

  script_name("Oracle: Security Advisory (ELSA-2015-1981)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=(OracleLinux6|OracleLinux7)");

  script_xref(name:"Advisory-ID", value:"ELSA-2015-1981");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2015-1981.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'nspr, nss, nss-util' package(s) announced via the ELSA-2015-1981 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"nspr
[4.10.8-2]
- Resolves: Bug 1269360 - CVE-2015-7183
- nspr: heap-buffer overflow in PL_ARENA_ALLOCATE can lead to crash (under ASAN), potential memory corruption

nss
[3.19.1-5.0.1]
- Added nss-vendor.patch to change vendor

[3.19.1-5]
- Rebuild against updated NSPR

[3.19.1-4]
- Sync up with the rhel-6.6 branch
- Resolves: Bug 1224450

nss-util
[3.19.1-2]
- Resolves: Bug 1269355 - CVE-2015-7182 CVE-2015-7181");

  script_tag(name:"affected", value:"'nspr, nss, nss-util' package(s) on Oracle Linux 6, Oracle Linux 7.");

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

if(release == "OracleLinux6") {

  if(!isnull(res = isrpmvuln(pkg:"nspr", rpm:"nspr~4.10.8~2.el6_7", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nspr-devel", rpm:"nspr-devel~4.10.8~2.el6_7", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nss", rpm:"nss~3.19.1~5.0.1.el6_7", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nss-devel", rpm:"nss-devel~3.19.1~5.0.1.el6_7", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nss-pkcs11-devel", rpm:"nss-pkcs11-devel~3.19.1~5.0.1.el6_7", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nss-sysinit", rpm:"nss-sysinit~3.19.1~5.0.1.el6_7", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nss-tools", rpm:"nss-tools~3.19.1~5.0.1.el6_7", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nss-util", rpm:"nss-util~3.19.1~2.el6_7", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nss-util-devel", rpm:"nss-util-devel~3.19.1~2.el6_7", rls:"OracleLinux6"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "OracleLinux7") {

  if(!isnull(res = isrpmvuln(pkg:"nspr", rpm:"nspr~4.10.8~2.el7_1", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nspr-devel", rpm:"nspr-devel~4.10.8~2.el7_1", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nss", rpm:"nss~3.19.1~7.0.1.el7_1.2", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nss-devel", rpm:"nss-devel~3.19.1~7.0.1.el7_1.2", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nss-pkcs11-devel", rpm:"nss-pkcs11-devel~3.19.1~7.0.1.el7_1.2", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nss-sysinit", rpm:"nss-sysinit~3.19.1~7.0.1.el7_1.2", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nss-tools", rpm:"nss-tools~3.19.1~7.0.1.el7_1.2", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nss-util", rpm:"nss-util~3.19.1~4.el7_1", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nss-util-devel", rpm:"nss-util-devel~3.19.1~4.el7_1", rls:"OracleLinux7"))) {
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
