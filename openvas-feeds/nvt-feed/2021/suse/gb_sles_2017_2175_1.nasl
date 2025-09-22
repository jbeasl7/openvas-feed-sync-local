# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2017.2175.1");
  script_cve_id("CVE-2017-10053", "CVE-2017-10067", "CVE-2017-10074", "CVE-2017-10078", "CVE-2017-10081", "CVE-2017-10086", "CVE-2017-10087", "CVE-2017-10089", "CVE-2017-10090", "CVE-2017-10096", "CVE-2017-10101", "CVE-2017-10102", "CVE-2017-10105", "CVE-2017-10107", "CVE-2017-10108", "CVE-2017-10109", "CVE-2017-10110", "CVE-2017-10111", "CVE-2017-10114", "CVE-2017-10115", "CVE-2017-10116", "CVE-2017-10118", "CVE-2017-10125", "CVE-2017-10135", "CVE-2017-10176", "CVE-2017-10193", "CVE-2017-10198", "CVE-2017-10243");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-08-15 19:22:01 +0000 (Tue, 15 Aug 2017)");

  script_name("SUSE: Security Advisory (SUSE-SU-2017:2175-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP1|SLES12\.0SP2|SLES12\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2017:2175-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2017/suse-su-20172175-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1049302");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1049305");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1049306");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1049307");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1049308");
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
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2017-August/003139.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'java-1_8_0-openjdk' package(s) announced via the SUSE-SU-2017:2175-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This java-1_8_0-openjdk update to version jdk8u141 (icedtea 3.5.0) fixes the following issues:

Security issues fixed:
- CVE-2017-10053: Improved image post-processing steps (bsc#1049305)
- CVE-2017-10067: Additional jar validation steps (bsc#1049306)
- CVE-2017-10074: Image conversion improvements (bsc#1049307)
- CVE-2017-10078: Better script accessibility for JavaScript (bsc#1049308)
- CVE-2017-10081: Right parenthesis issue (bsc#1049309)
- CVE-2017-10086: Unspecified vulnerability in subcomponent JavaFX (bsc#1049310)
- CVE-2017-10087: Better Thread Pool execution (bsc#1049311)
- CVE-2017-10089: Service Registration Lifecycle (bsc#1049312)
- CVE-2017-10090: Better handling of channel groups (bsc#1049313)
- CVE-2017-10096: Transform Transformer Exceptions (bsc#1049314)
- CVE-2017-10101: Better reading of text catalogs (bsc#1049315)
- CVE-2017-10102: Improved garbage collection (bsc#1049316)
- CVE-2017-10105: Unspecified vulnerability in subcomponent deployment (bsc#1049317)
- CVE-2017-10107: Less Active Activations (bsc#1049318)
- CVE-2017-10108: Better naming attribution (bsc#1049319)
- CVE-2017-10109: Better sourcing of code (bsc#1049320)
- CVE-2017-10110: Better image fetching (bsc#1049321)
- CVE-2017-10111: Rearrange MethodHandle arrangements (bsc#1049322)
- CVE-2017-10114: Unspecified vulnerability in subcomponent JavaFX (bsc#1049323)
- CVE-2017-10115: Higher quality DSA operations (bsc#1049324)
- CVE-2017-10116: Proper directory lookup processing (bsc#1049325)
- CVE-2017-10118: Higher quality ECDSA operations (bsc#1049326)
- CVE-2017-10125: Unspecified vulnerability in subcomponent deployment (bsc#1049327)
- CVE-2017-10135: Better handling of PKCS8 material (bsc#1049328)
- CVE-2017-10176: Additional elliptic curve support (bsc#1049329)
- CVE-2017-10193: Improve algorithm constraints implementation (bsc#1049330)
- CVE-2017-10198: Clear certificate chain connections (bsc#1049331)
- CVE-2017-10243: Unspecified vulnerability in subcomponent JAX-WS (bsc#1049332)

Bug fixes:
- Check registry registration location
- Improved certificate processing
- JMX diagnostic improvements
- Update to libpng 1.6.28
- Import of OpenJDK 8 u141 build 15 (bsc#1049302)

New features:
- Support using RSAandMGF1 with the SHA hash algorithms in the PKCS11 provider");

  script_tag(name:"affected", value:"'java-1_8_0-openjdk' package(s) on SUSE Linux Enterprise Desktop 12-SP2, SUSE Linux Enterprise Desktop 12-SP3, SUSE Linux Enterprise Server 12-SP1, SUSE Linux Enterprise Server 12-SP2, SUSE Linux Enterprise Server 12-SP3, SUSE Linux Enterprise Server for Raspberry Pi 12-SP2, SUSE Linux Enterprise Server for SAP Applications 12-SP1, SUSE Linux Enterprise Server for SAP Applications 12-SP2, SUSE Linux Enterprise Server for SAP Applications 12-SP3.");

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

if(release == "SLES12.0SP1") {

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-openjdk", rpm:"java-1_8_0-openjdk~1.8.0.144~27.5.3", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-openjdk-demo", rpm:"java-1_8_0-openjdk-demo~1.8.0.144~27.5.3", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-openjdk-devel", rpm:"java-1_8_0-openjdk-devel~1.8.0.144~27.5.3", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-openjdk-headless", rpm:"java-1_8_0-openjdk-headless~1.8.0.144~27.5.3", rls:"SLES12.0SP1"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-openjdk", rpm:"java-1_8_0-openjdk~1.8.0.144~27.5.3", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-openjdk-demo", rpm:"java-1_8_0-openjdk-demo~1.8.0.144~27.5.3", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-openjdk-devel", rpm:"java-1_8_0-openjdk-devel~1.8.0.144~27.5.3", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-openjdk-headless", rpm:"java-1_8_0-openjdk-headless~1.8.0.144~27.5.3", rls:"SLES12.0SP2"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-openjdk", rpm:"java-1_8_0-openjdk~1.8.0.144~27.5.3", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-openjdk-demo", rpm:"java-1_8_0-openjdk-demo~1.8.0.144~27.5.3", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-openjdk-devel", rpm:"java-1_8_0-openjdk-devel~1.8.0.144~27.5.3", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-openjdk-headless", rpm:"java-1_8_0-openjdk-headless~1.8.0.144~27.5.3", rls:"SLES12.0SP3"))) {
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
