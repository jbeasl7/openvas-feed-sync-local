# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.123876");
  script_tag(name:"creation_date", value:"2015-10-06 11:09:44 +0000 (Tue, 06 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"Greenbone");
  script_tag(name:"severity_date", value:"2022-01-11 11:33:45 +0000 (Tue, 11 Jan 2022)");

  script_name("Oracle: Security Advisory (ELSA-2012-0973)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux6");

  script_xref(name:"Advisory-ID", value:"ELSA-2012-0973");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2012-0973.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'nspr, nss, nss-util' package(s) announced via the ELSA-2012-0973 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"nspr
[4.9-1]
- Resolves: rhbz#799193 - Update to 4.9

nss
[3.13.3-6.0.1.el6]
- Added nss-vendor.patch to change vendor
- Use blank image instead of clean.gif in tar ball

[3.13.3-6]
- Resolves: #rhbz#805232 PEM module may attempt to free uninitialized pointer

[3.13.3-5]
- Resolves: rhbz#717913 - [PEM] various flaws detected by Coverity
- Require nss-util 3.13.3

[3.13.3-4]
- Resolves: rhbz#772628 nss_Init leaks memory

[3.13.3-3]
- Resolves: rhbz#746632 - pem_CreateObject mem leak on non existing file name
- Use completed patch per code review

[3.13.3-2]
- Resolves: rhbz#746632 - pem_CreateObject mem leak on non existing file name
- Resolves: rhbz#768669 - PEM unregistered callback causes SIGSEGV

[3.13.3-1]
- Update to 3.13.3
- Resolves: rhbz#798539 - Distrust MITM subCAs issued by TrustWave
- Remove builtins-nssckbi_1_88_rtm.patch which the rebase obsoletes

nss-util
[3.13.3-2]
- Resolves: rhbz#799192 - Update to 3.13.3
- Update minimum nspr version for Requires and BuildRequires to 4.9
- Fix version/release in changelog to match the Version and Release tags, now 3.13.3-2

[3.13.1-5]
- Resolves: rhbz#799192 - Update to 3.13.3");

  script_tag(name:"affected", value:"'nspr, nss, nss-util' package(s) on Oracle Linux 6.");

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

  if(!isnull(res = isrpmvuln(pkg:"nspr", rpm:"nspr~4.9~1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nspr-devel", rpm:"nspr-devel~4.9~1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nss", rpm:"nss~3.13.3~6.0.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nss-devel", rpm:"nss-devel~3.13.3~6.0.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nss-pkcs11-devel", rpm:"nss-pkcs11-devel~3.13.3~6.0.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nss-sysinit", rpm:"nss-sysinit~3.13.3~6.0.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nss-tools", rpm:"nss-tools~3.13.3~6.0.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nss-util", rpm:"nss-util~3.13.3~2.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nss-util-devel", rpm:"nss-util-devel~3.13.3~2.el6", rls:"OracleLinux6"))) {
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
