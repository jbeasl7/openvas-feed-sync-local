# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2020.2861.1");
  script_cve_id("CVE-2020-14577", "CVE-2020-14578", "CVE-2020-14579", "CVE-2020-14581", "CVE-2020-14583", "CVE-2020-14593", "CVE-2020-14621");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"5.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-07-20 18:30:24 +0000 (Mon, 20 Jul 2020)");

  script_name("SUSE: Security Advisory (SUSE-SU-2020:2861-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP2|SLES12\.0SP3|SLES12\.0SP4|SLES12\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2020:2861-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2020/suse-su-20202861-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1174157");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2020-October/007522.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'java-1_7_0-openjdk' package(s) announced via the SUSE-SU-2020:2861-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for java-1_7_0-openjdk fixes the following issues:

- java-1_7_0-openjdk was updated to 2.6.23 (July 2020 CPU, bsc#1174157)
 - JDK-8028431, CVE-2020-14579: NullPointerException in
 - DerValue.equals(DerValue)
 - JDK-8028591, CVE-2020-14578: NegativeArraySizeException in
 - sun.security.util.DerInputStream.getUnalignedBitString()
 - JDK-8230613: Better ASCII conversions
 - JDK-8231800: Better listing of arrays
 - JDK-8232014: Expand DTD support
 - JDK-8233255: Better Swing Buttons
 - JDK-8234032: Improve basic calendar services
 - JDK-8234042: Better factory production of certificates
 - JDK-8234418: Better parsing with CertificateFactory
 - JDK-8234836: Improve serialization handling
 - JDK-8236191: Enhance OID processing
 - JDK-8237592, CVE-2020-14577: Enhance certificate verification
 - JDK-8238002, CVE-2020-14581: Better matrix operations
 - JDK-8238804: Enhance key handling process
 - JDK-8238842: AIOOBE in GIFImageReader.initializeStringTable
 - JDK-8238843: Enhanced font handing
 - JDK-8238920, CVE-2020-14583: Better Buffer support
 - JDK-8238925: Enhance WAV file playback
 - JDK-8240119, CVE-2020-14593: Less Affine Transformations
 - JDK-8240482: Improved WAV file playback
 - JDK-8241379: Update JCEKS support
 - JDK-8241522: Manifest improved jar headers redux
 - JDK-8242136, CVE-2020-14621: Better XML namespace handling
 - JDK-8040113: File not initialized in src/share/native/sun/awt/giflib/dgif_lib.c
 - JDK-8054446: Repeated offer and remove on ConcurrentLinkedQueue lead to an OutOfMemoryError
 - JDK-8077982: GIFLIB upgrade
 - JDK-8081315: 8077982 giflib upgrade breaks system giflib builds with earlier versions
 - JDK-8147087: Race when reusing PerRegionTable bitmaps may result in dropped remembered set entries
 - JDK-8151582: (ch) test java/nio/channels/AsyncCloseAndInterrupt.java failing due to 'Connection succeeded'
 - JDK-8155691: Update GIFlib library to the latest up-to-date
 - JDK-8181841: A TSA server returns timestamp with precision higher than milliseconds
 - JDK-8203190: SessionId.hashCode generates too many collisions
 - JDK-8217676: Upgrade libpng to 1.6.37
 - JDK-8220495: Update GIFlib library to the 5.1.8
 - JDK-8226892: ActionListeners on JRadioButtons don't get notified when selection is changed with arrow keys
 - JDK-8229899: Make java.io.File.isInvalid() less racy
 - JDK-8230597: Update GIFlib library to the 5.2.1
 - JDK-8230769: BufImg_SetupICM add ReleasePrimitiveArrayCritical call in early return
 - JDK-8243541: (tz) Upgrade time-zone data to tzdata2020a
 - JDK-8244548: JDK 8u: sun.misc.Version.jdkUpdateVersion() returns wrong result");

  script_tag(name:"affected", value:"'java-1_7_0-openjdk' package(s) on SUSE Linux Enterprise Server 12-SP2, SUSE Linux Enterprise Server 12-SP3, SUSE Linux Enterprise Server 12-SP4, SUSE Linux Enterprise Server 12-SP5, SUSE Linux Enterprise Server for SAP Applications 12-SP2, SUSE Linux Enterprise Server for SAP Applications 12-SP3, SUSE Linux Enterprise Server for SAP Applications 12-SP4, SUSE Linux Enterprise Server for SAP Applications 12-SP5.");

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

if(release == "SLES12.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"java-1_7_0-openjdk", rpm:"java-1_7_0-openjdk~1.7.0.271~43.41.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_7_0-openjdk-demo", rpm:"java-1_7_0-openjdk-demo~1.7.0.271~43.41.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_7_0-openjdk-devel", rpm:"java-1_7_0-openjdk-devel~1.7.0.271~43.41.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_7_0-openjdk-headless", rpm:"java-1_7_0-openjdk-headless~1.7.0.271~43.41.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES12.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"java-1_7_0-openjdk", rpm:"java-1_7_0-openjdk~1.7.0.271~43.41.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_7_0-openjdk-demo", rpm:"java-1_7_0-openjdk-demo~1.7.0.271~43.41.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_7_0-openjdk-devel", rpm:"java-1_7_0-openjdk-devel~1.7.0.271~43.41.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_7_0-openjdk-headless", rpm:"java-1_7_0-openjdk-headless~1.7.0.271~43.41.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES12.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"java-1_7_0-openjdk", rpm:"java-1_7_0-openjdk~1.7.0.271~43.41.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_7_0-openjdk-demo", rpm:"java-1_7_0-openjdk-demo~1.7.0.271~43.41.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_7_0-openjdk-devel", rpm:"java-1_7_0-openjdk-devel~1.7.0.271~43.41.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_7_0-openjdk-headless", rpm:"java-1_7_0-openjdk-headless~1.7.0.271~43.41.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES12.0SP5") {

  if(!isnull(res = isrpmvuln(pkg:"java-1_7_0-openjdk", rpm:"java-1_7_0-openjdk~1.7.0.271~43.41.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_7_0-openjdk-demo", rpm:"java-1_7_0-openjdk-demo~1.7.0.271~43.41.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_7_0-openjdk-devel", rpm:"java-1_7_0-openjdk-devel~1.7.0.271~43.41.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_7_0-openjdk-headless", rpm:"java-1_7_0-openjdk-headless~1.7.0.271~43.41.1", rls:"SLES12.0SP5"))) {
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
