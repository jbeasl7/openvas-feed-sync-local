# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2020.3460.1");
  script_cve_id("CVE-2020-14556", "CVE-2020-14577", "CVE-2020-14578", "CVE-2020-14579", "CVE-2020-14581", "CVE-2020-14583", "CVE-2020-14593", "CVE-2020-14621", "CVE-2020-14779", "CVE-2020-14781", "CVE-2020-14782", "CVE-2020-14792", "CVE-2020-14796", "CVE-2020-14797", "CVE-2020-14798", "CVE-2020-14803");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-10-28 01:17:40 +0000 (Wed, 28 Oct 2020)");

  script_name("SUSE: Security Advisory (SUSE-SU-2020:3460-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP1|SLES15\.0SP2|SLES15\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2020:3460-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2020/suse-su-20203460-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1174157");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1177943");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2020-November/007829.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'java-1_8_0-openjdk' package(s) announced via the SUSE-SU-2020:3460-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for java-1_8_0-openjdk fixes the following issues:

- Fix regression '8250861: Crash in MinINode::Ideal(PhaseGVN*, bool)',
 introduced in October 2020 CPU.

- Update to version jdk8u272 (icedtea 3.17.0) (July 2020 CPU,
 bsc#1174157, and October 2020 CPU, bsc#1177943)
 * New features
 + JDK-8245468: Add TLSv1.3 implementation classes from 11.0.7
 + PR3796: Allow the number of curves supported to be specified
 * Security fixes
 + JDK-8028431, CVE-2020-14579: NullPointerException in
 DerValue.equals(DerValue)
 + JDK-8028591, CVE-2020-14578: NegativeArraySizeException in
 sun.security.util.DerInputStream.getUnalignedBitString()
 + JDK-8230613: Better ASCII conversions
 + JDK-8231800: Better listing of arrays
 + JDK-8232014: Expand DTD support
 + JDK-8233255: Better Swing Buttons
 + JDK-8233624: Enhance JNI linkage
 + JDK-8234032: Improve basic calendar services
 + JDK-8234042: Better factory production of certificates
 + JDK-8234418: Better parsing with CertificateFactory
 + JDK-8234836: Improve serialization handling
 + JDK-8236191: Enhance OID processing
 + JDK-8236196: Improve string pooling
 + JDK-8236862, CVE-2020-14779: Enhance support of Proxy class
 + JDK-8237117, CVE-2020-14556: Better ForkJoinPool behavior
 + JDK-8237592, CVE-2020-14577: Enhance certificate verification
 + JDK-8237990, CVE-2020-14781: Enhanced LDAP contexts
 + JDK-8237995, CVE-2020-14782: Enhance certificate processing
 + JDK-8238002, CVE-2020-14581: Better matrix operations
 + JDK-8238804: Enhance key handling process
 + JDK-8238842: AIOOBE in GIFImageReader.initializeStringTable
 + JDK-8238843: Enhanced font handing
 + JDK-8238920, CVE-2020-14583: Better Buffer support
 + JDK-8238925: Enhance WAV file playback
 + JDK-8240119, CVE-2020-14593: Less Affine Transformations
 + JDK-8240124: Better VM Interning
 + JDK-8240482: Improved WAV file playback
 + JDK-8241114, CVE-2020-14792: Better range handling
 + JDK-8241379: Update JCEKS support
 + JDK-8241522: Manifest improved jar headers redux
 + JDK-8242136, CVE-2020-14621: Better XML namespace handling
 + JDK-8242680, CVE-2020-14796: Improved URI Support
 + JDK-8242685, CVE-2020-14797: Better Path Validation
 + JDK-8242695, CVE-2020-14798: Enhanced buffer support
 + JDK-8243302: Advanced class supports
 + JDK-8244136, CVE-2020-14803: Improved Buffer supports
 + JDK-8244479: Further constrain certificates
 + JDK-8244955: Additional Fix for JDK-8240124
 + JDK-8245407: Enhance zoning of times
 + JDK-8245412: Better class definitions
 + JDK-8245417: Improve certificate chain handling
 + JDK-8248574: Improve jpeg processing
 + JDK-8249927: Specify limits of jdk.serialProxyInterfaceLimit
 + JDK-8253019: Enhanced JPEG decoding
 * Import of OpenJDK 8 u262 build 01
 + JDK-4949105: Access Bridge lacks html tags parsing
 + JDK-8003209: JFR events for network utilization
 + JDK-8030680: 292 cleanup from default method code assessment
 + JDK-8035633: ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'java-1_8_0-openjdk' package(s) on SUSE Linux Enterprise Server 15, SUSE Linux Enterprise Server for SAP Applications 15.");

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

if(release == "SLES15.0SP1") {

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-openjdk", rpm:"java-1_8_0-openjdk~1.8.0.272~3.42.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-openjdk-debuginfo", rpm:"java-1_8_0-openjdk-debuginfo~1.8.0.272~3.42.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-openjdk-debugsource", rpm:"java-1_8_0-openjdk-debugsource~1.8.0.272~3.42.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-openjdk-demo", rpm:"java-1_8_0-openjdk-demo~1.8.0.272~3.42.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-openjdk-demo-debuginfo", rpm:"java-1_8_0-openjdk-demo-debuginfo~1.8.0.272~3.42.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-openjdk-devel", rpm:"java-1_8_0-openjdk-devel~1.8.0.272~3.42.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-openjdk-devel-debuginfo", rpm:"java-1_8_0-openjdk-devel-debuginfo~1.8.0.272~3.42.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-openjdk-headless", rpm:"java-1_8_0-openjdk-headless~1.8.0.272~3.42.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-openjdk-headless-debuginfo", rpm:"java-1_8_0-openjdk-headless-debuginfo~1.8.0.272~3.42.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES15.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-openjdk", rpm:"java-1_8_0-openjdk~1.8.0.272~3.42.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-openjdk-debuginfo", rpm:"java-1_8_0-openjdk-debuginfo~1.8.0.272~3.42.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-openjdk-debugsource", rpm:"java-1_8_0-openjdk-debugsource~1.8.0.272~3.42.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-openjdk-demo", rpm:"java-1_8_0-openjdk-demo~1.8.0.272~3.42.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-openjdk-demo-debuginfo", rpm:"java-1_8_0-openjdk-demo-debuginfo~1.8.0.272~3.42.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-openjdk-devel", rpm:"java-1_8_0-openjdk-devel~1.8.0.272~3.42.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-openjdk-devel-debuginfo", rpm:"java-1_8_0-openjdk-devel-debuginfo~1.8.0.272~3.42.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-openjdk-headless", rpm:"java-1_8_0-openjdk-headless~1.8.0.272~3.42.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-openjdk-headless-debuginfo", rpm:"java-1_8_0-openjdk-headless-debuginfo~1.8.0.272~3.42.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES15.0") {

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-openjdk", rpm:"java-1_8_0-openjdk~1.8.0.272~3.42.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-openjdk-demo", rpm:"java-1_8_0-openjdk-demo~1.8.0.272~3.42.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-openjdk-devel", rpm:"java-1_8_0-openjdk-devel~1.8.0.272~3.42.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-openjdk-headless", rpm:"java-1_8_0-openjdk-headless~1.8.0.272~3.42.1", rls:"SLES15.0"))) {
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
