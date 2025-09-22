# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.123238");
  script_tag(name:"creation_date", value:"2015-10-06 11:01:08 +0000 (Tue, 06 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"Greenbone");
  script_tag(name:"severity_date", value:"2022-01-11 11:33:45 +0000 (Tue, 11 Jan 2022)");

  script_name("Oracle: Security Advisory (ELSA-2014-1948)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=(OracleLinux5|OracleLinux6|OracleLinux7)");

  script_xref(name:"Advisory-ID", value:"ELSA-2014-1948");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2014-1948.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'nss, nss-softokn, nss-util' package(s) announced via the ELSA-2014-1948 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"nss
[3.16.2.3-2.0.1.el7_0]
- Added nss-vendor.patch to change vendor

[3.16.2.3-2]
- Restore patch for certutil man page
- supply missing options descriptions
- Resolves: Bug 1165525 - Upgrade to NSS 3.16.2.3 for Firefox 31.3

[3.16.2.3-1]
- Resolves: Bug 1165525 - Upgrade to NSS 3.16.2.3 for Firefox 31.3
- Support TLS_FALLBACK_SCSV in tstclnt and ssltap

[3.16.2-8]
- Fix crash in stan_GetCERTCertificate
- Resolves: Bug 1139349

nss-softokn
[3.16.2-3]
- Resolves: Bug 1165525 - Upgrade to NSS 3.16.2.3 for Firefox 31.3

[3.16.2-3]
- Resolves: Bug 1145433 - CVE-2014-1568

[3.16.2-1]
- Update to nss-3.16.2
- Resolves: Bug 1124659 - Rebase RHEL 7.1 to at least NSS-SOFTOKN 3.16.1 (FF 31)

[3.15.4-2]
- Mass rebuild 2014-01-24

[3.15.3-4]
- Rebase to nss-3.15.4
- Resolves: Bug 1054457 - CVE-2013-1740
- Update softokn splitting script to oparate on the upstream pristine source
- Using the .gz archives directly, not repackageing as .bz2 ones
- Avoid unneeded manual steps that could introduce errors
- Update the iquote and build softoken only patches on account of the rebase

[3.15.3-3]
- Fix to allow level 1 fips mode if the db has no password
- Resolves: Bug 852023 - FIPS mode detection does not work

[3.15.3-2]
- Mass rebuild 2013-12-27

[3.15.3-1]
- Rebase to NSS_3_15_3_RTM
- Related: Bug 1031463 - CVE-2013-5605 CVE-2013-5606 CVE-2013-1741

[3.15.2-2]
- Resolves: rhbz#1020395 - Allow Level 1 FIPS mode if the nss db has no password

[3.15.2-1]
- Rebase to nss-softoken from nss-3.15.2
- Resolves: rhbz#1012679 - pick up NSS-SOFTOKN 3.15.2 (required for bug 1012656)

[3.15.1-3]
- Add export NSS_ENABLE_ECC=1 rto the %build and %check sections
- Resolves: rhbz#752980 - [7.0 FEAT] Support ECDSA algorithm in the nss package

[3.15.1-2]
- Remove an obsolete script and adjust the sources numbering accordingly

[3.15.1-1]
- Update to NSS_3_15_1_RTM

[3.15-4]
- Split off nss-softokn from the unstripped nss source tar ball

[3.15-3]
- Update to NSS_3_15_RTM
- Require nspr-4.10 or greater
- Fix patch that selects tests to run

[3.15-0.1.beta.3]
- Reverse the last changes since pk11gcmtest properly belongs to nss

[3.15-0.1.beta.2]
- Add lowhashtest and pk11gcmtest as unsupported tools
- Modify nss-softoken-split script to include them in the split

[3.15-0.1.beta.1]
- Update to NSS_3_15_BETA1
- Update spec file, patches, and helper scripts on account of a shallwer source tree

nss-util
[3.16.2.1-1]
- Resolves: Bug 1165525 - Upgrade to NSS 3.16.2.3 for Firefox 31.3");

  script_tag(name:"affected", value:"'nss, nss-softokn, nss-util' package(s) on Oracle Linux 5, Oracle Linux 6, Oracle Linux 7.");

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

  if(!isnull(res = isrpmvuln(pkg:"nss", rpm:"nss~3.16.2.3~1.el5_11", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nss-devel", rpm:"nss-devel~3.16.2.3~1.el5_11", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nss-pkcs11-devel", rpm:"nss-pkcs11-devel~3.16.2.3~1.el5_11", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nss-tools", rpm:"nss-tools~3.16.2.3~1.el5_11", rls:"OracleLinux5"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "OracleLinux6") {

  if(!isnull(res = isrpmvuln(pkg:"nss", rpm:"nss~3.16.2.3~3.0.1.el6_6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nss-devel", rpm:"nss-devel~3.16.2.3~3.0.1.el6_6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nss-pkcs11-devel", rpm:"nss-pkcs11-devel~3.16.2.3~3.0.1.el6_6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nss-sysinit", rpm:"nss-sysinit~3.16.2.3~3.0.1.el6_6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nss-tools", rpm:"nss-tools~3.16.2.3~3.0.1.el6_6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nss-util", rpm:"nss-util~3.16.2.3~2.el6_6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nss-util-devel", rpm:"nss-util-devel~3.16.2.3~2.el6_6", rls:"OracleLinux6"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"nss", rpm:"nss~3.16.2.3~2.0.1.el7_0", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nss-devel", rpm:"nss-devel~3.16.2.3~2.0.1.el7_0", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nss-pkcs11-devel", rpm:"nss-pkcs11-devel~3.16.2.3~2.0.1.el7_0", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nss-softokn", rpm:"nss-softokn~3.16.2.3~1.el7_0", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nss-softokn-devel", rpm:"nss-softokn-devel~3.16.2.3~1.el7_0", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nss-softokn-freebl", rpm:"nss-softokn-freebl~3.16.2.3~1.el7_0", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nss-softokn-freebl-devel", rpm:"nss-softokn-freebl-devel~3.16.2.3~1.el7_0", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nss-sysinit", rpm:"nss-sysinit~3.16.2.3~2.0.1.el7_0", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nss-tools", rpm:"nss-tools~3.16.2.3~2.0.1.el7_0", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nss-util", rpm:"nss-util~3.16.2.3~1.el7_0", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nss-util-devel", rpm:"nss-util-devel~3.16.2.3~1.el7_0", rls:"OracleLinux7"))) {
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
