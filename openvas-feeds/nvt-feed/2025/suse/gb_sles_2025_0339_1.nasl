# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2025.0339.1");
  script_cve_id("CVE-2025-21502");
  script_tag(name:"creation_date", value:"2025-02-04 04:25:57 +0000 (Tue, 04 Feb 2025)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-01-21 21:15:15 +0000 (Tue, 21 Jan 2025)");

  script_name("SUSE: Security Advisory (SUSE-SU-2025:0339-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP4|SLES15\.0SP5|SLES15\.0SP6)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:0339-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-20250339-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1236278");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2025-February/020259.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'java-17-openjdk' package(s) announced via the SUSE-SU-2025:0339-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"- CVE-2025-21502: Enhance array handling (JDK-8330045, bsc#1236278)

Other changes:

- JDK-7093691: Nimbus LAF: disabled JComboBox using renderer has bad font color
- JDK-8028127: Regtest java/security/Security/SynchronizedAccess.java is incorrect
- JDK-8071693: Introspector ignores default interface methods
- JDK-8195675: Call to insertText with single character from custom Input Method ignored
- JDK-8202926: Test java/awt/Focus/WindowUpdateFocusabilityTest/WindowUpdateFocusabilityTest.html fails
- JDK-8207908: JMXStatusTest.java fails assertion intermittently
- JDK-8225220: When the Tab Policy is checked,the scroll button direction displayed incorrectly.
- JDK-8240343: JDI stopListening/stoplis001 'FAILED: listening is successfully stopped without starting listening'
- JDK-8254759: [TEST_BUG] [macosx] javax/swing/JInternalFrame/4202966/IntFrameCoord.html fails
- JDK-8258734: jdk/jfr/event/oldobject/TestClassLoaderLeak.java failed with 'RuntimeException: Could not find class leak'
- JDK-8268364: jmethod clearing should be done during unloading
- JDK-8269770: nsk tests should start IOPipe channel before launch debuggee - Debugee.prepareDebugee
- JDK-8271003: hs_err improvement: handle CLASSPATH env setting longer than O_BUFLEN
- JDK-8271456: Avoid looking up standard charsets in 'java.desktop' module
- JDK-8271821: mark hotspot runtime/MinimalVM tests which ignore external VM flags
- JDK-8271825: mark hotspot runtime/LoadClass tests which ignore external VM flags
- JDK-8271836: runtime/ErrorHandling/ClassPathEnvVar.java fails with release VMs
- JDK-8272746: ZipFile can't open big file (NegativeArraySizeException)
- JDK-8273914: Indy string concat changes order of operations
- JDK-8274170: Add hooks for custom makefiles to augment jtreg test execution
- JDK-8274505: Too weak variable type leads to unnecessary cast in java.desktop
- JDK-8276763: java/nio/channels/SocketChannel/AdaptorStreams.java fails with 'SocketTimeoutException: Read timed out'
- JDK-8278527: java/util/concurrent/tck/JSR166TestCase.java fails nanoTime test
- JDK-8280131: jcmd reports 'Module jdk.jfr not found.' when 'jdk.management.jfr' is missing
- JDK-8281379: Assign package declarations to all jtreg test cases under gc
- JDK-8282578: AIOOBE in javax.sound.sampled.Clip
- JDK-8283214: [macos] Screen magnifier does not show the magnified text for JComboBox
- JDK-8283222: improve diagnosability of runtime/8176717/TestInheritFD.java timeouts
- JDK-8284291: sun/security/krb5/auto/Renew.java fails intermittently on Windows 11
- JDK-8284874: Add comment to ProcessHandle/OnExitTest to describe zombie problem
- JDK-8286160: (fs) Files.exists returns unexpected results with C:\pagefile.sys because it's not readable
- JDK-8287003: InputStreamReader::read() can return zero despite writing a char in the buffer
- JDK-8288976: classfile parser 'wrong name' error message has the names the wrong way around
- ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'java-17-openjdk' package(s) on SUSE Linux Enterprise Server 15-SP4, SUSE Linux Enterprise Server 15-SP5, SUSE Linux Enterprise Server 15-SP6, SUSE Linux Enterprise Server for SAP Applications 15-SP4, SUSE Linux Enterprise Server for SAP Applications 15-SP5.");

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

if(release == "SLES15.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"java-17-openjdk", rpm:"java-17-openjdk~17.0.14.0~150400.3.51.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-17-openjdk-demo", rpm:"java-17-openjdk-demo~17.0.14.0~150400.3.51.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-17-openjdk-devel", rpm:"java-17-openjdk-devel~17.0.14.0~150400.3.51.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-17-openjdk-headless", rpm:"java-17-openjdk-headless~17.0.14.0~150400.3.51.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES15.0SP5") {

  if(!isnull(res = isrpmvuln(pkg:"java-17-openjdk", rpm:"java-17-openjdk~17.0.14.0~150400.3.51.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-17-openjdk-demo", rpm:"java-17-openjdk-demo~17.0.14.0~150400.3.51.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-17-openjdk-devel", rpm:"java-17-openjdk-devel~17.0.14.0~150400.3.51.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-17-openjdk-headless", rpm:"java-17-openjdk-headless~17.0.14.0~150400.3.51.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES15.0SP6") {

  if(!isnull(res = isrpmvuln(pkg:"java-17-openjdk", rpm:"java-17-openjdk~17.0.14.0~150400.3.51.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-17-openjdk-devel", rpm:"java-17-openjdk-devel~17.0.14.0~150400.3.51.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-17-openjdk-headless", rpm:"java-17-openjdk-headless~17.0.14.0~150400.3.51.1", rls:"SLES15.0SP6"))) {
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
