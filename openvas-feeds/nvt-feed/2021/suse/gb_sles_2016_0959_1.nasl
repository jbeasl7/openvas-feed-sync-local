# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2016.0959.1");
  script_cve_id("CVE-2016-0636");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:24+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:24 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-03-25 14:59:37 +0000 (Fri, 25 Mar 2016)");

  script_name("SUSE: Security Advisory (SUSE-SU-2016:0959-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0|SLES12\.0SP1)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2016:0959-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2016/suse-su-20160959-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/972468");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2016-April/001986.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'java-1_7_0-openjdk' package(s) announced via the SUSE-SU-2016:0959-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The OpenJDK Java java-1_7_0-openjdk was updated to 2.6.5 to fix the following issues:

Update to 2.6.5 - OpenJDK 7u99 (bsc#972468)
* Security fixes
 - S8152335, CVE-2016-0636: Improve MethodHandle consistency
* Import of OpenJDK 7 u99 build 0
 - S6425769, PR2858: Allow specifying an address to bind JMX
 remote connector
 - S6961123: setWMClass fails to null-terminate WM_CLASS string
 - S8145982, PR2858: JMXInterfaceBindingTest is failing
 intermittently
 - S8146015, PR2858: JMXInterfaceBindingTest is failing
 intermittently for IPv6 addresses
* Backports
 - S8028727, PR2814: [parfait] warnings from b116 for
 jdk.src.share.native.sun.security.ec: JNI pending exceptions
 - S8048512, PR2814: Uninitialised memory in
 jdk/src/share/native/sun/security/ec/ECC_JNI.cpp
 - S8071705. PR2819, RH1182694: Java application menu misbehaves
 when running multiple screen stacked vertically
 - S8150954, PR2866, RH1176206: AWT Robot not compatible with
 GNOME Shell
* Bug fixes
 - PR2803: Make system CUPS optional
 - PR2886: Location of 'stap' executable is hard-coded
 - PR2893: test/tapset/jstaptest.pl should be executable
 - PR2894: Add missing test directory in make check.
* CACAO
 - PR2781, CA195: typeinfo.cpp: typeinfo_merge_nonarrays:
 Assertion `dest && result && x.any && y.any' failed
* AArch64 port
 - PR2852: Add support for large code cache
 - PR2852: Apply ReservedCodeCacheSize default limiting to
 AArch64 only.
 - S8081289, PR2852: aarch64: add support for
 RewriteFrequentPairs in interpreter
 - S8131483, PR2852: aarch64: illegal stlxr instructions
 - S8133352, PR2852: aarch64: generates constrained unpredictable
 instructions
 - S8133842, PR2852: aarch64: C2 generates illegal instructions
 with int shifts >=32
 - S8134322, PR2852: AArch64: Fix several errors in C2 biased
 locking implementation
 - S8136615, PR2852: aarch64: elide DecodeN when followed by
 CmpP 0
 - S8138575, PR2852: Improve generated code for profile counters
 - S8138641, PR2852: Disable C2 peephole by default for aarch64
 - S8138966, PR2852: Intermittent SEGV running ParallelGC
 - S8143067, PR2852: aarch64: guarantee failure in javac
 - S8143285, PR2852: aarch64: Missing load acquire when checking
 if ConstantPoolCacheEntry is resolved
 - S8143584, PR2852: Load constant pool tag and class status with
 load acquire
 - S8144201, PR2852: aarch64:
 jdk/test/com/sun/net/httpserver/Test6a.java fails with
 --enable-unlimited-crypto
 - S8144582, PR2852: AArch64 does not generate correct branch
 profile data
 - S8146709, PR2852: AArch64: Incorrect use of ADRP for
 byte_map_base
 - S8147805, PR2852: aarch64: C1 segmentation fault due to inline
 Unsafe.getAndSetObject
 - S8148240, PR2852: aarch64: random infrequent null pointer
 exceptions in javac
* PPC & AIX port
 - S8034797, PR2851: AIX: Fix os::naked_short_sleep() in
 os_aix.cpp after 8028280
 - S8139258, PR2851: PPC64LE: argument passing problem when
 passing 15 ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'java-1_7_0-openjdk' package(s) on SUSE Linux Enterprise Desktop 12, SUSE Linux Enterprise Desktop 12-SP1, SUSE Linux Enterprise Server 12, SUSE Linux Enterprise Server 12-SP1, SUSE Linux Enterprise Server for SAP Applications 12, SUSE Linux Enterprise Server for SAP Applications 12-SP1.");

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

  if(!isnull(res = isrpmvuln(pkg:"java-1_7_0-openjdk", rpm:"java-1_7_0-openjdk~1.7.0.99~27.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_7_0-openjdk-demo", rpm:"java-1_7_0-openjdk-demo~1.7.0.99~27.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_7_0-openjdk-devel", rpm:"java-1_7_0-openjdk-devel~1.7.0.99~27.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_7_0-openjdk-headless", rpm:"java-1_7_0-openjdk-headless~1.7.0.99~27.1", rls:"SLES12.0"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"java-1_7_0-openjdk", rpm:"java-1_7_0-openjdk~1.7.0.99~27.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_7_0-openjdk-demo", rpm:"java-1_7_0-openjdk-demo~1.7.0.99~27.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_7_0-openjdk-devel", rpm:"java-1_7_0-openjdk-devel~1.7.0.99~27.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_7_0-openjdk-headless", rpm:"java-1_7_0-openjdk-headless~1.7.0.99~27.1", rls:"SLES12.0SP1"))) {
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
