# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2018.0005.1");
  script_cve_id("CVE-2016-10165", "CVE-2016-9840", "CVE-2016-9841", "CVE-2016-9842", "CVE-2016-9843", "CVE-2017-10053", "CVE-2017-10067", "CVE-2017-10074", "CVE-2017-10081", "CVE-2017-10086", "CVE-2017-10087", "CVE-2017-10089", "CVE-2017-10090", "CVE-2017-10096", "CVE-2017-10101", "CVE-2017-10102", "CVE-2017-10105", "CVE-2017-10107", "CVE-2017-10108", "CVE-2017-10109", "CVE-2017-10110", "CVE-2017-10111", "CVE-2017-10114", "CVE-2017-10115", "CVE-2017-10116", "CVE-2017-10118", "CVE-2017-10125", "CVE-2017-10135", "CVE-2017-10176", "CVE-2017-10193", "CVE-2017-10198", "CVE-2017-10243", "CVE-2017-10274", "CVE-2017-10281", "CVE-2017-10285", "CVE-2017-10295", "CVE-2017-10345", "CVE-2017-10346", "CVE-2017-10347", "CVE-2017-10348", "CVE-2017-10349", "CVE-2017-10350", "CVE-2017-10355", "CVE-2017-10356", "CVE-2017-10357", "CVE-2017-10388");
  script_tag(name:"creation_date", value:"2021-06-09 14:57:49 +0000 (Wed, 09 Jun 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-06-01 16:47:18 +0000 (Thu, 01 Jun 2017)");

  script_name("SUSE: Security Advisory (SUSE-SU-2018:0005-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0|SLES12\.0SP1|SLES12\.0SP2|SLES12\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2018:0005-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2018/suse-su-20180005-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1049305");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1049306");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1049307");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1049309");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1049310");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1049311");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1049312");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1049313");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1049314");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1049315");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1049316");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1049317");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1049318");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1049319");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1049320");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1049321");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1049322");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1049323");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1049324");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1049325");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1049326");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1049327");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1049328");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1049329");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1049330");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1049331");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1049332");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1052318");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1064071");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1064072");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1064073");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1064075");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1064077");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1064078");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1064079");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1064080");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1064081");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1064082");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1064083");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1064084");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1064085");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1064086");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-updates/2018-January/007678.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'java-1_7_0-openjdk' package(s) announced via the SUSE-SU-2018:0005-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for java-1_7_0-openjdk fixes the following issues:

Security issues fixed:

- CVE-2017-10356: Fix issue inside subcomponent Security (bsc#1064084).
- CVE-2017-10274: Fix issue inside subcomponent Smart Card IO (bsc#1064071).
- CVE-2017-10281: Fix issue inside subcomponent Serialization (bsc#1064072).
- CVE-2017-10285: Fix issue inside subcomponent RMI (bsc#1064073).
- CVE-2017-10295: Fix issue inside subcomponent Networking (bsc#1064075).
- CVE-2017-10388: Fix issue inside subcomponent Libraries (bsc#1064086).
- CVE-2017-10346: Fix issue inside subcomponent Hotspot (bsc#1064078).
- CVE-2017-10350: Fix issue inside subcomponent JAX-WS (bsc#1064082).
- CVE-2017-10347: Fix issue inside subcomponent Serialization (bsc#1064079).
- CVE-2017-10349: Fix issue inside subcomponent JAXP (bsc#1064081).
- CVE-2017-10345: Fix issue inside subcomponent Serialization (bsc#1064077).
- CVE-2017-10348: Fix issue inside subcomponent Libraries (bsc#1064080).
- CVE-2017-10357: Fix issue inside subcomponent Serialization (bsc#1064085).
- CVE-2017-10355: Fix issue inside subcomponent Networking (bsc#1064083).
- CVE-2017-10102: Fix incorrect handling of references in DGC (bsc#1049316).
- CVE-2017-10053: Fix reading of unprocessed image data in JPEGImageReader (bsc#1049305).
- CVE-2017-10067: Fix JAR verifier incorrect handling of missing digest (bsc#1049306).
- CVE-2017-10081: Fix incorrect bracket processing in function signature handling (bsc#1049309).
- CVE-2017-10087: Fix insufficient access control checks in ThreadPoolExecutor (bsc#1049311).
- CVE-2017-10089: Fix insufficient access control checks in ServiceRegistry (bsc#1049312).
- CVE-2017-10090: Fix insufficient access control checks in AsynchronousChannelGroupImpl (bsc#1049313).
- CVE-2017-10096: Fix insufficient access control checks in XML transformations (bsc#1049314).
- CVE-2017-10101: Fix unrestricted access to com.sun.org.apache.xml.internal.resolver (bsc#1049315).
- CVE-2017-10107: Fix insufficient access control checks in ActivationID (bsc#1049318).
- CVE-2017-10074: Fix integer overflows in range check loop predicates (bsc#1049307).
- CVE-2017-10110: Fix insufficient access control checks in ImageWatched (bsc#1049321).
- CVE-2017-10108: Fix unbounded memory allocation in BasicAttribute deserialization (bsc#1049319).
- CVE-2017-10109: Fix unbounded memory allocation in CodeSource deserialization (bsc#1049320).
- CVE-2017-10115: Fix unspecified vulnerability in subcomponent JCE (bsc#1049324).
- CVE-2017-10118: Fix ECDSA implementation timing attack (bsc#1049326).
- CVE-2017-10116: Fix LDAPCertStore following referrals to non-LDAP URL (bsc#1049325).
- CVE-2017-10135: Fix PKCS#8 implementation timing attack (bsc#1049328).
- CVE-2017-10176: Fix incorrect handling of certain EC points (bsc#1049329).
- CVE-2017-10074: Fix integer overflows in range check loop predicates (bsc#1049307).
- CVE-2017-10074: Fix integer ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'java-1_7_0-openjdk' package(s) on SUSE Linux Enterprise Desktop 12-SP2, SUSE Linux Enterprise Desktop 12-SP3, SUSE Linux Enterprise Server 12, SUSE Linux Enterprise Server 12-SP1, SUSE Linux Enterprise Server 12-SP2, SUSE Linux Enterprise Server 12-SP3, SUSE Linux Enterprise Server for Raspberry Pi 12-SP2, SUSE Linux Enterprise Server for SAP Applications 12, SUSE Linux Enterprise Server for SAP Applications 12-SP1, SUSE Linux Enterprise Server for SAP Applications 12-SP2, SUSE Linux Enterprise Server for SAP Applications 12-SP3.");

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

if(release == "SLES12.0") {

  if(!isnull(res = isrpmvuln(pkg:"java-1_7_0-openjdk", rpm:"java-1_7_0-openjdk~1.7.0.161~43.7.6", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_7_0-openjdk-demo", rpm:"java-1_7_0-openjdk-demo~1.7.0.161~43.7.6", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_7_0-openjdk-devel", rpm:"java-1_7_0-openjdk-devel~1.7.0.161~43.7.6", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_7_0-openjdk-headless", rpm:"java-1_7_0-openjdk-headless~1.7.0.161~43.7.6", rls:"SLES12.0"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES12.0SP1") {

  if(!isnull(res = isrpmvuln(pkg:"java-1_7_0-openjdk", rpm:"java-1_7_0-openjdk~1.7.0.161~43.7.6", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_7_0-openjdk-demo", rpm:"java-1_7_0-openjdk-demo~1.7.0.161~43.7.6", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_7_0-openjdk-devel", rpm:"java-1_7_0-openjdk-devel~1.7.0.161~43.7.6", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_7_0-openjdk-headless", rpm:"java-1_7_0-openjdk-headless~1.7.0.161~43.7.6", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES12.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"java-1_7_0-openjdk", rpm:"java-1_7_0-openjdk~1.7.0.161~43.7.6", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_7_0-openjdk-demo", rpm:"java-1_7_0-openjdk-demo~1.7.0.161~43.7.6", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_7_0-openjdk-devel", rpm:"java-1_7_0-openjdk-devel~1.7.0.161~43.7.6", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_7_0-openjdk-headless", rpm:"java-1_7_0-openjdk-headless~1.7.0.161~43.7.6", rls:"SLES12.0SP2"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"java-1_7_0-openjdk", rpm:"java-1_7_0-openjdk~1.7.0.161~43.7.6", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_7_0-openjdk-demo", rpm:"java-1_7_0-openjdk-demo~1.7.0.161~43.7.6", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_7_0-openjdk-devel", rpm:"java-1_7_0-openjdk-devel~1.7.0.161~43.7.6", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_7_0-openjdk-headless", rpm:"java-1_7_0-openjdk-headless~1.7.0.161~43.7.6", rls:"SLES12.0SP3"))) {
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
