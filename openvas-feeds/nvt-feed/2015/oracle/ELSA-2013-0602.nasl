# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.123679");
  script_cve_id("CVE-2013-0809", "CVE-2013-1493");
  script_tag(name:"creation_date", value:"2015-10-06 11:07:08 +0000 (Tue, 06 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Oracle: Security Advisory (ELSA-2013-0602)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux6");

  script_xref(name:"Advisory-ID", value:"ELSA-2013-0602");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2013-0602.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'java-1.7.0-openjdk' package(s) announced via the ELSA-2013-0602 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[1.7.0.9-2.3.8.0.0.1.el6_4]
- Update DISTRO_NAME in specfile

[1.7.0.9-2.3.8.0el6]
- Revert to rhel 6.3 version of spec file
- Revert to icedtea7 2.3.8 forest
- Resolves: rhbz#917183

[1.7.0.11-2.4.0.pre5.el6]
- Update to latest snapshot of icedtea7 2.4 forest
- Resolves: rhbz#917183

[1.7.0.9-2.4.0.pre4.3.el6]
- Updated to icedtea 2.4.0.pre4,
- Rewritten (again) patch3 java-1.7.0-openjdk-java-access-bridge-security.patch
- Resolves: rhbz#911530

[1.7.0.9-2.4.0.pre3.3.el6]
- Updated to icedtea 2.4.0.pre3, updated!
- Rewritten patch3 java-1.7.0-openjdk-java-access-bridge-security.patch
- Resolves: rhbz#911530

[1.7.0.9-2.4.0.pre2.3.el6]
- Removed testing
 - mauve was outdated and
 - jtreg was icedtea relict
- Updated to icedtea 2.4.0.pre2, updated?
- Added java -Xshare:dump to post (see 513605)forjitarchs
- Resolves: rhbz#911530

[1.7.0.11-2.4.0.2.el6]
- Unapplied but kept (for 2.3revert) patch110, java-1.7.0-openjdk-nss-icedtea-e9c857dcb964.patch
- Added and applied patch113: java-1.7.0-openjdk-aes-update_reset.patch
- Added and applied patch114: java-1.7.0-openjdk-nss-tck.patch
- Added and applied patch115: java-1.7.0-openjdk-nss-split_results.patch
- NSS enabled by default - enable_nss set to 1
- rewritten patch109 - java-1.7.0-openjdk-nss-config-1.patch
- rewritten patch111 - java-1.7.0-openjdk-nss-config-2.patch
- Resolves: rhbz#831734

[1.7.0.11-2.4.0.1.el6]
- Rewritten patch105: java-1.7.0-openjdk-disable-system-lcms.patch
- Added jxmd and idlj to alternatives
- make executed with DISABLE_INTREE_EC=true and UNLIMITED_CRYPTO=true
- Unapplied patch302 and deleted systemtap.patch
- buildver increased to 11
- icedtea_version set to 2.4.0
- Added and applied patch112 java-1.7.openjdk-doNotUseDisabledEcc.patch
- removed tmp-patches source tarball
- Added /lib/security/US_export_policy.jar and lib/security/local_policy.jar
- Disabled nss - enable_nss set to 0
- Resolves: rhbz#895034");

  script_tag(name:"affected", value:"'java-1.7.0-openjdk' package(s) on Oracle Linux 6.");

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

  if(!isnull(res = isrpmvuln(pkg:"java-1.7.0-openjdk", rpm:"java-1.7.0-openjdk~1.7.0.9~2.3.8.0.0.1.el6_4", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1.7.0-openjdk-demo", rpm:"java-1.7.0-openjdk-demo~1.7.0.9~2.3.8.0.0.1.el6_4", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1.7.0-openjdk-devel", rpm:"java-1.7.0-openjdk-devel~1.7.0.9~2.3.8.0.0.1.el6_4", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1.7.0-openjdk-javadoc", rpm:"java-1.7.0-openjdk-javadoc~1.7.0.9~2.3.8.0.0.1.el6_4", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1.7.0-openjdk-src", rpm:"java-1.7.0-openjdk-src~1.7.0.9~2.3.8.0.0.1.el6_4", rls:"OracleLinux6"))) {
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
