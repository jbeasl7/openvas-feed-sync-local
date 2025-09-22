# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2025.1399.1");
  script_cve_id("CVE-2025-21587", "CVE-2025-30691", "CVE-2025-30698");
  script_tag(name:"creation_date", value:"2025-05-01 04:10:38 +0000 (Thu, 01 May 2025)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-04-15 21:15:54 +0000 (Tue, 15 Apr 2025)");

  script_name("SUSE: Security Advisory (SUSE-SU-2025:1399-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:1399-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-20251399-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1241274");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1241275");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1241276");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-updates/2025-April/039103.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'java-11-openjdk' package(s) announced via the SUSE-SU-2025:1399-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for java-11-openjdk fixes the following issues:

Upgrade to upstream tag jdk-11.0.27+6 (April 2025 CPU)

CVEs:

+ CVE-2025-21587: Fixed JSSE unauthorized access, deletion or modification of critical data (bsc#1241274)
+ CVE-2025-30691: Fixed Oracle Java SE Compiler Unauthorized Data Access (bsc#1241275)
+ CVE-2025-30698: Fixed Oracle Java 2D unauthorized data access and DoS (bsc#1241276)

Changes:

 + JDK-8195675: Call to insertText with single character
 from custom Input Method ignored
 + JDK-8202926: Test java/awt/Focus/
 /WindowUpdateFocusabilityTest/
 /WindowUpdateFocusabilityTest.html fails
 + JDK-8216539: tools/jar/modularJar/Basic.java timed out
 + JDK-8268364: jmethod clearing should be done during
 unloading
 + JDK-8273914: Indy string concat changes order of
 operations
 + JDK-8294316: SA core file support is broken on macosx-x64
 starting with macOS 12.x
 + JDK-8306408: Fix the format of several tables in
 building.md
 + JDK-8309841: Jarsigner should print a warning if an entry
 is removed
 + JDK-8312049: runtime/logging/ClassLoadUnloadTest can be
 improved
 + JDK-8320916: jdk/jfr/event/gc/stacktrace/
 /TestParallelMarkSweepAllocationPendingStackTrace.java failed
 with 'OutOfMemoryError: GC overhead limit exceeded'
 + JDK-8327650: Test java/nio/channels/DatagramChannel/
 /StressNativeSignal.java timed out
 + JDK-8328242: Add a log area to the PassFailJFrame
 + JDK-8331863: DUIterator_Fast used before it is constructed
 + JDK-8336012: Fix usages of jtreg-reserved properties
 + JDK-8337494: Clarify JarInputStream behavior
 + JDK-8337692: Better TLS connection support
 + JDK-8338430: Improve compiler transformations
 + JDK-8339560: Unaddressed comments during code review of
 JDK-8337664
 + JDK-8339810: Clean up the code in sun.tools.jar.Main to
 properly close resources and use ZipFile during extract
 + JDK-8339931: Update problem list for
 WindowUpdateFocusabilityTest.java
 + JDK-8340387: Update OS detection code to recognize
 Windows Server 2025
 + JDK-8341424: GHA: Collect hs_errs from build time failures
 + JDK-8342562: Enhance Deflater operations
 + JDK-8342704: GHA: Report truncation is broken after
 JDK-8341424
 + JDK-8343007: Enhance Buffered Image handling
 + JDK-8343474: [updates] Customize README.md to specifics
 of update project
 + JDK-8343599: Kmem limit and max values swapped when
 printing container information
 + JDK-8343786: [11u] GHA: Bump macOS and Xcode versions to
 macos-13 and XCode 14.3.1
 + JDK-8344589: Update IANA Language Subtag Registry to
 Version 2024-11-19
 + JDK-8345509: Bump update version of OpenJDK: 11.0.27
 + JDK-8346587: Distrust TLS server certificates anchored by
 Camerfirma Root CAs
 + JDK-8347427: JTabbedPane/8134116/Bug8134116.java has no
 license header
 + JDK-8347847: Enhance jar file support
 + JDK-8347965: (tz) Update Timezone Data to 2025a
 + JDK-8349603: [21u, 17u, 11u] Update GHA JDKs after Jan/25
 ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'java-11-openjdk' package(s) on SUSE Linux Enterprise Server 12-SP5.");

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

if(release == "SLES12.0SP5") {

  if(!isnull(res = isrpmvuln(pkg:"java-11-openjdk", rpm:"java-11-openjdk~11.0.27.0~3.87.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-11-openjdk-demo", rpm:"java-11-openjdk-demo~11.0.27.0~3.87.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-11-openjdk-devel", rpm:"java-11-openjdk-devel~11.0.27.0~3.87.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-11-openjdk-headless", rpm:"java-11-openjdk-headless~11.0.27.0~3.87.1", rls:"SLES12.0SP5"))) {
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
