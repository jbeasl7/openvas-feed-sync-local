# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2016.2887.1");
  script_cve_id("CVE-2016-5542", "CVE-2016-5554", "CVE-2016-5556", "CVE-2016-5568", "CVE-2016-5573", "CVE-2016-5582", "CVE-2016-5597");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-10-27 18:39:36 +0000 (Thu, 27 Oct 2016)");

  script_name("SUSE: Security Advisory (SUSE-SU-2016:2887-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP1|SLES12\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2016:2887-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2016/suse-su-20162887-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1005522");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1005523");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1005524");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1005525");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1005526");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1005527");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1005528");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/988651");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2016-November/002412.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'java-1_8_0-openjdk' package(s) announced via the SUSE-SU-2016:2887-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"OpenJDK Java was updated to jdk8u111 (icedtea 3.2.0) to fix the following issues:

* Security fixes
 + S8146490: Direct indirect CRL checks
 + S8151921: Improved page resolution
 + S8155968: Update command line options
 + S8155973, CVE-2016-5542: Tighten jar checks (bsc#1005522)
 + S8156794: Extend data sharing
 + S8157176: Improved classfile parsing
 + S8157739, CVE-2016-5554: Classloader Consistency Checking
 (bsc#1005523)
 + S8157749: Improve handling of DNS error replies
 + S8157753: Audio replay enhancement
 + S8157759: LCMS Transform Sampling Enhancement
 + S8157764: Better handling of interpolation plugins
 + S8158302: Handle contextual glyph substitutions
 + S8158993, CVE-2016-5568: Service Menu services (bsc#1005525)
 + S8159495: Fix index offsets
 + S8159503: Amend Annotation Actions
 + S8159511: Stack map validation
 + S8159515: Improve indy validation
 + S8159519, CVE-2016-5573: Reformat JDWP messages (bsc#1005526)
 + S8160090: Better signature handling in pack200
 + S8160094: Improve pack200 layout
 + S8160098: Clean up color profiles
 + S8160591, CVE-2016-5582: Improve internal array handling
 (bsc#1005527)
 + S8160838, CVE-2016-5597: Better HTTP service (bsc#1005528)
 + PR3206, RH1367357: lcms2: Out-of-bounds read in
 Type_MLU_Read()
 + CVE-2016-5556 (bsc#1005524)
* New features
 + PR1370: Provide option to build without debugging
 + PR1375: Provide option to strip and link debugging info after
 build
 + PR1537: Handle alternative Kerberos credential cache
 locations
 + PR1978: Allow use of system PCSC
 + PR2445: Support system libsctp
 + PR3182: Support building without pre-compiled headers
 + PR3183: Support Fedora/RHEL system crypto policy
 + PR3221: Use pkgconfig to detect Kerberos CFLAGS and libraries
* Import of OpenJDK 8 u102 build 14
 + S4515292: ReferenceType.isStatic() returns true for arrays
 + S4858370: JDWP: Memory Leak: GlobalRefs never deleted when
 processing invokeMethod command
 + S6976636: JVM/TI test ex03t001 fails assertion
 + S7185591: jcmd-big-script.sh ERROR: could not find app's Java
 pid.
 + S8017462: G1: guarantee fails with
 UseDynamicNumberOfGCThreads
 + S8034168: ThreadMXBean/Locks.java failed, blocked on wrong
 object
 + S8036006: [TESTBUG] sun/tools/native2ascii/NativeErrors.java
 fails: Process exit code was 0, but error was expected.
 + S8041781: Need new regression tests for PBE keys
 + S8041787: Need new regressions tests for buffer handling for
 PBE algorithms
 + S8043836: Need new tests for AES cipher
 + S8044199: Tests for RSA keys and key specifications
 + S8044772: TempDirTest.java still times out with -Xcomp
 + S8046339: sun.rmi.transport.DGCAckHandler leaks memory
 + S8047031: Add SocketPermission tests for legacy socket types
 + S8048052: Permission tests for setFactory
 + S8048138: Tests for JAAS callbacks
 + S8048147: Privilege tests with JAAS Subject.doAs
 + S8048356: SecureRandom default provider tests
 + ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'java-1_8_0-openjdk' package(s) on SUSE Linux Enterprise Desktop 12-SP1, SUSE Linux Enterprise Desktop 12-SP2, SUSE Linux Enterprise Server 12-SP1, SUSE Linux Enterprise Server 12-SP2, SUSE Linux Enterprise Server for Raspberry Pi 12-SP2, SUSE Linux Enterprise Server for SAP Applications 12-SP1, SUSE Linux Enterprise Server for SAP Applications 12-SP2.");

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

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-openjdk", rpm:"java-1_8_0-openjdk~1.8.0.111~17.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-openjdk-demo", rpm:"java-1_8_0-openjdk-demo~1.8.0.111~17.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-openjdk-devel", rpm:"java-1_8_0-openjdk-devel~1.8.0.111~17.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-openjdk-headless", rpm:"java-1_8_0-openjdk-headless~1.8.0.111~17.1", rls:"SLES12.0SP1"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-openjdk", rpm:"java-1_8_0-openjdk~1.8.0.111~17.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-openjdk-demo", rpm:"java-1_8_0-openjdk-demo~1.8.0.111~17.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-openjdk-devel", rpm:"java-1_8_0-openjdk-devel~1.8.0.111~17.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-openjdk-headless", rpm:"java-1_8_0-openjdk-headless~1.8.0.111~17.1", rls:"SLES12.0SP2"))) {
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
