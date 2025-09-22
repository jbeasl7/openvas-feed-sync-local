# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2025.0279.1");
  script_cve_id("CVE-2025-21502");
  script_tag(name:"creation_date", value:"2025-06-04 14:43:37 +0000 (Wed, 04 Jun 2025)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-01-21 21:15:15 +0000 (Tue, 21 Jan 2025)");

  script_name("SUSE: Security Advisory (SUSE-SU-2025:0279-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP6)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:0279-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-20250279-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1236278");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2025-January/020230.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'java-21-openjdk' package(s) announced via the SUSE-SU-2025:0279-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"- CVE-2025-21502: Enhance array handling (JDK-8330045, bsc#1236278)

Other changes:

- JDK-6942632: Hotspot should be able to use more than 64 logical processors on Windows
- JDK-8028127: Regtest java/security/Security/SynchronizedAccess.java is incorrect
- JDK-8195675: Call to insertText with single character from custom Input Method ignored
- JDK-8207908: JMXStatusTest.java fails assertion intermittently
- JDK-8225220: When the Tab Policy is checked,the scroll button direction displayed incorrectly.
- JDK-8240343: JDI stopListening/stoplis001 'FAILED: listening is successfully stopped without starting listening'
- JDK-8283214: [macos] Screen magnifier does not show the magnified text for JComboBox
- JDK-8296787: Unify debug printing format of X.509 cert serial numbers
- JDK-8296972: [macos13] java/awt/Frame/MaximizedToIconified/MaximizedToIconified.java: getExtendedState() != 6 as expected.
- JDK-8306446: java/lang/management/ThreadMXBean/Locks.java transient failures
- JDK-8308429: jvmti/StopThread/stopthrd007 failed with 'NoClassDefFoundError: Could not initialize class jdk.internal.misc.VirtualThreads'
- JDK-8309218: java/util/concurrent/locks/Lock/OOMEInAQS.java still times out with ZGC, Generational ZGC, and SerialGC
- JDK-8311301: MethodExitTest may fail with stack buffer overrun
- JDK-8311656: Shenandoah: Unused ShenandoahSATBAndRemarkThreadsClosure::_claim_token
- JDK-8312518: [macos13] setFullScreenWindow() shows black screen on macOS 13 & above
- JDK-8313374: --enable-ccache's CCACHE_BASEDIR breaks builds
- JDK-8313878: Exclude two compiler/rtm/locking tests on ppc64le
- JDK-8315701: [macos] Regression: KeyEvent has different keycode on different keyboard layouts
- JDK-8316428: G1: Nmethod count statistics only count last code root set iterated
- JDK-8316893: Compile without -fno-delete-null-pointer-checks
- JDK-8316895: SeenThread::print_action_queue called on a null pointer
- JDK-8316907: Fix nonnull-compare warnings
- JDK-8317116: Provide layouts for multiple test UI in PassFailJFrame
- JDK-8317575: AArch64: C2_MacroAssembler::fast_lock uses rscratch1 for cmpxchg result
- JDK-8318105: [jmh] the test java.security.HSS failed with 2 active threads
- JDK-8318442: java/net/httpclient/ManyRequests2.java fails intermittently on Linux
- JDK-8319640: ClassicFormat::parseObject (from DateTimeFormatter) does not conform to the javadoc and may leak DateTimeException
- JDK-8319673: Few security tests ignore VM flags
- JDK-8319678: Several tests from corelibs areas ignore VM flags
- JDK-8319960: RISC-V: compiler/intrinsics/TestInteger/LongUnsignedDivMod.java failed with 'counts: Graph contains wrong number of nodes'
- JDK-8319970: AArch64: enable tests compiler/intrinsics/Test(Long<pipe>Integer)UnsignedDivMod.java on aarch64
- JDK-8319973: AArch64: Save and restore FPCR in the call stub
- JDK-8320192: SHAKE256 does not work correctly if n >= 137
- JDK-8320397: RISC-V: ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'java-21-openjdk' package(s) on SUSE Linux Enterprise Server 15-SP6.");

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

if(release == "SLES15.0SP6") {

  if(!isnull(res = isrpmvuln(pkg:"java-21-openjdk", rpm:"java-21-openjdk~21.0.6.0~150600.3.9.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-21-openjdk-demo", rpm:"java-21-openjdk-demo~21.0.6.0~150600.3.9.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-21-openjdk-devel", rpm:"java-21-openjdk-devel~21.0.6.0~150600.3.9.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-21-openjdk-headless", rpm:"java-21-openjdk-headless~21.0.6.0~150600.3.9.1", rls:"SLES15.0SP6"))) {
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
