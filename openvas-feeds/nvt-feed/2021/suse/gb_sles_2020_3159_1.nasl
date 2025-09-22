# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2020.3159.1");
  script_cve_id("CVE-2020-14779", "CVE-2020-14781", "CVE-2020-14782", "CVE-2020-14792", "CVE-2020-14796", "CVE-2020-14797", "CVE-2020-14798", "CVE-2020-14803");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-10-28 01:17:40 +0000 (Wed, 28 Oct 2020)");

  script_name("SUSE: Security Advisory (SUSE-SU-2020:3159-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2020:3159-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2020/suse-su-20203159-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1177943");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2020-November/007697.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'java-11-openjdk' package(s) announced via the SUSE-SU-2020:3159-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for java-11-openjdk fixes the following issues:

- Update to upstream tag jdk-11.0.9-11 (October 2020 CPU,
 bsc#1177943)
 * New features
 + JDK-8250784: Shenandoah: A Low-Pause-Time Garbage Collector
 * Security fixes
 + JDK-8233624: Enhance JNI linkage
 + JDK-8236196: Improve string pooling
 + JDK-8236862, CVE-2020-14779: Enhance support of Proxy class
 + JDK-8237990, CVE-2020-14781: Enhanced LDAP contexts
 + JDK-8237995, CVE-2020-14782: Enhance certificate processing
 + JDK-8240124: Better VM Interning
 + JDK-8241114, CVE-2020-14792: Better range handling
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
 * Other changes
 + JDK-6532025: GIF reader throws misleading exception with
 truncated images
 + JDK-6949753: [TEST BUG]: java/awt/print/PageFormat/
 /PDialogTest.java needs update by removing an infinite loop
 + JDK-8022535: [TEST BUG] javax/swing/text/html/parser/
 /Test8017492.java fails
 + JDK-8062947: Fix exception message to correctly represent
 LDAP connection failure
 + JDK-8067354: com/sun/jdi/GetLocalVariables4Test.sh failed
 + JDK-8134599: TEST_BUG: java/rmi/transport/closeServerSocket/
 /CloseServerSocket.java fails intermittently with Address
 already in use
 + JDK-8151678: com/sun/jndi/ldap/LdapTimeoutTest.java failed
 due to timeout on DeadServerNoTimeoutTest is incorrect
 + JDK-8160768: Add capability to custom resolve host/domain
 names within the default JNDI LDAP provider
 + JDK-8172404: Tools should warn if weak algorithms are used
 before restricting them
 + JDK-8193367: Annotated type variable bounds crash javac
 + JDK-8202117: com/sun/jndi/ldap/RemoveNamingListenerTest.java
 fails intermittently: Connection reset
 + JDK-8203026: java.rmi.NoSuchObjectException: no such object
 in table
 + JDK-8203281: [Windows] JComboBox change in ui when
 editor.setBorder() is called
 + JDK-8203382: Rename SystemDictionary::initialize_wk_klass to
 resolve_wk_klass
 + JDK-8203393: com/sun/jdi/JdbMethodExitTest.sh and
 JdbExprTest.sh fail due to timeout
 + JDK-8203928: [Test] Convert non-JDB scaffolding
 serviceability shell script tests to java
 + JDK-8204963: javax.swing.border.TitledBorder has a memory leak
 + JDK-8204994: SA might fail to attach to process with 'Windbg
 Error: WaitForEvent failed'
 + JDK-8205534: Remove SymbolTable dependency from
 serviceability agent
 + ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'java-11-openjdk' package(s) on SUSE Linux Enterprise Server 12-SP5, SUSE Linux Enterprise Server for SAP Applications 12-SP5.");

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

  if(!isnull(res = isrpmvuln(pkg:"java-11-openjdk", rpm:"java-11-openjdk~11.0.9.0~3.15.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-11-openjdk-demo", rpm:"java-11-openjdk-demo~11.0.9.0~3.15.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-11-openjdk-devel", rpm:"java-11-openjdk-devel~11.0.9.0~3.15.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-11-openjdk-headless", rpm:"java-11-openjdk-headless~11.0.9.0~3.15.1", rls:"SLES12.0SP5"))) {
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
