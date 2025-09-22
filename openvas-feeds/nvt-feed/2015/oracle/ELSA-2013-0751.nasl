# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.123639");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2013-0401", "CVE-2013-1488", "CVE-2013-1518", "CVE-2013-1537", "CVE-2013-1557", "CVE-2013-1558", "CVE-2013-1569", "CVE-2013-2383", "CVE-2013-2384", "CVE-2013-2415", "CVE-2013-2417", "CVE-2013-2419", "CVE-2013-2420", "CVE-2013-2421", "CVE-2013-2422", "CVE-2013-2423", "CVE-2013-2424", "CVE-2013-2426", "CVE-2013-2429", "CVE-2013-2430", "CVE-2013-2431", "CVE-2013-2436");
  script_tag(name:"creation_date", value:"2015-10-06 11:06:38 +0000 (Tue, 06 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Oracle: Security Advisory (ELSA-2013-0751)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux6");

  script_xref(name:"Advisory-ID", value:"ELSA-2013-0751");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2013-0751.html");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=904231");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=721033");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=902227");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=679180");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=918172");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'java-1.7.0-openjdk' package(s) announced via the ELSA-2013-0751 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[1.7.0.19-2.3.9.1.0.1.el6_4]
- Update DISTRO_NAME in specfile

[1.7.0.19-2.3.9.1.el6]
- updated to updated IcedTea 2.3.9 with fix to one of security fixes
 - fixed font glyph offset
- Resolves: rhbz#950380

[1.7.0.9-2.3.9.0.el6]
- updated to IcedTea 2.3.9 with latest security patches
- buildver sync to b19
- rewritten java-1.7.0-openjdk-java-access-bridge-security.patch
- Resolves: rhbz#950380

[1.7.0.19-2.3.8.2.el6]
- Added latest Fedora spec changes
- Bumped release
- Removed patch2 java-1.7.0-openjdk-java-access-bridge-idlj.patch (unapplied)
- zlib in BuildReq restricted for 1.2.3-7 or higher
 - see [link moved to references]
- Removed a -icedtea tag from the version
 - package have less and less connections to icedtea7
- Added gcc-c++ build dependence. Sometimes caused troubles during rpm -bb
- Added (Build)Requires for fontconfig and xorg-x11-fonts-Type1
 - see [link moved to references] for details
- Removed all fonconfig files. Fonts are now handled differently in JDK
 and those files are redundant. This is going to be usptreamed.
 - see [link moved to references] for details
- logging.properties marked as config(noreplace)
 - see [link moved to references] for details
- classes.jsa marked as ghost on full path
 - see [link moved to references] for details
- nss.cfg was marked as config(noreplace)
- Add symlink to default soundfont (see 541466)
- Resolves: rhbz#950380

[1.7.0.9-2.3.8.1.el6]
- Added and applied patch 116 - patch 116 rh905128-non_block_ciphers.patch
- Added and applied patch 117 - patch 117 java-1.7.0-openjdk-nss-multiplePKCS11libraryInitialisationNnonCritical.patch
 - to enable handleStartupErrors = ignoreMultipleInitialisation in icedtea 2.3
- Restorered removed nss support
- Fixed java-1.7.0-openjdk-nss-config-{1,2} patches to be valid for icedtea 2.3.x
- enable_nss switch to 0 - disabled
- Resolves: rhbz#950380");

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

  if(!isnull(res = isrpmvuln(pkg:"java-1.7.0-openjdk", rpm:"java-1.7.0-openjdk~1.7.0.19~2.3.9.1.0.1.el6_4", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1.7.0-openjdk-demo", rpm:"java-1.7.0-openjdk-demo~1.7.0.19~2.3.9.1.0.1.el6_4", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1.7.0-openjdk-devel", rpm:"java-1.7.0-openjdk-devel~1.7.0.19~2.3.9.1.0.1.el6_4", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1.7.0-openjdk-javadoc", rpm:"java-1.7.0-openjdk-javadoc~1.7.0.19~2.3.9.1.0.1.el6_4", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1.7.0-openjdk-src", rpm:"java-1.7.0-openjdk-src~1.7.0.19~2.3.9.1.0.1.el6_4", rls:"OracleLinux6"))) {
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
