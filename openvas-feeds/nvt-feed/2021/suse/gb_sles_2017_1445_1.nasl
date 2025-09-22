# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2017.1445.1");
  script_cve_id("CVE-2017-3509", "CVE-2017-3511", "CVE-2017-3512", "CVE-2017-3514", "CVE-2017-3526", "CVE-2017-3533", "CVE-2017-3539", "CVE-2017-3544");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-05-04 17:49:35 +0000 (Thu, 04 May 2017)");

  script_name("SUSE: Security Advisory (SUSE-SU-2017:1445-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2017:1445-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2017/suse-su-20171445-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1034849");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2017-May/002928.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'java-1_8_0-openjdk' package(s) announced via the SUSE-SU-2017:1445-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for java-1_8_0-openjdk fixes the following issues:

- Upgrade to version jdk8u131 (icedtea 3.4.0) - bsc#1034849
 * Security fixes
 - S8163520, CVE-2017-3509: Reuse cache entries
 - S8163528, CVE-2017-3511: Better library loading
 - S8165626, CVE-2017-3512: Improved window framing
 - S8167110, CVE-2017-3514: Windows peering issue
 - S8168699: Validate special case invocations
 - S8169011, CVE-2017-3526: Resizing XML parse trees
 - S8170222, CVE-2017-3533: Better transfers of files
 - S8171121, CVE-2017-3539: Enhancing jar checking
 - S8171533, CVE-2017-3544: Better email transfer
 - S8172299: Improve class processing
 * New features
 - PR1969: Add AArch32 JIT port
 - PR3297: Allow Shenandoah to be used on AArch64
 - PR3340: jstack.stp should support AArch64
 * Import of OpenJDK 8 u131 build 11
 - S6474807: (smartcardio) CardTerminal.connect() throws
 CardException instead of CardNotPresentException
 - S6515172, PR3346: Runtime.availableProcessors() ignores Linux
 taskset command
 - S7155957:
 closed/java/awt/MenuBar/MenuBarStress1/MenuBarStress1.java
 hangs on win 64 bit with jdk8
 - S7167293: FtpURLConnection connection leak on
 FileNotFoundException
 - S8035568: [macosx] Cursor management unification
 - S8079595: Resizing dialog which is JWindow parent makes JVM
 crash
 - S8130769: The new menu can't be shown on the menubar after
 clicking the 'Add' button.
 - S8146602:
 jdk/test/sun/misc/URLClassPath/ClassnameCharTest.java test
 fails with NullPointerException
 - S8147842: IME Composition Window is displayed at incorrect
 location
 - S8147910, PR3346: Cache initial active_processor_count
 - S8150490: Update OS detection code to recognize Windows
 Server 2016
 - S8160951: [TEST_BUG]
 javax/xml/bind/marshal/8134111/UnmarshalTest.java should be
 added into :needs_jre group
 - S8160958: [TEST_BUG]
 java/net/SetFactoryPermission/SetFactoryPermission.java
 should be added into :needs_compact2 group
 - S8161147: jvm crashes when -XX:+UseCountedLoopSafepoints is
 enabled
 - S8161195: Regression:
 closed/javax/swing/text/FlowView/LayoutTest.java
 - S8161993, PR3346: G1 crashes if active_processor_count
 changes during startup
 - S8162876: [TEST_BUG]
 sun/net/www/protocol/http/HttpInputStream.java fails
 intermittently
 - S8162916: Test sun/security/krb5/auto/UnboundSSL.java fails
 - S8164533: sun/security/ssl/SSLSocketImpl/CloseSocket.java
 failed with 'Error while cleaning up threads after test'
 - S8167179: Make XSL generated namespace prefixes local to
 transformation process
 - S8168774: Polymorhic signature method check crashes javac
 - S8169465: Deadlock in com.sun.jndi.ldap.pool.Connections
 - S8169589: [macosx] Activating a JDialog puts to back another
 dialog
 - S8170307: Stack size option -Xss is ignored
 - S8170316: (tz) Support tzdata2016j
 - S8170814: Reuse cache entries (part II)
 - S8170888, PR3314, RH1284948: [linux] Experimental support for
 cgroup ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'java-1_8_0-openjdk' package(s) on SUSE Linux Enterprise Desktop 12-SP2, SUSE Linux Enterprise Server 12-SP2, SUSE Linux Enterprise Server for Raspberry Pi 12-SP2, SUSE Linux Enterprise Server for SAP Applications 12-SP2.");

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

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-openjdk", rpm:"java-1_8_0-openjdk~1.8.0.131~26.3", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-openjdk-demo", rpm:"java-1_8_0-openjdk-demo~1.8.0.131~26.3", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-openjdk-devel", rpm:"java-1_8_0-openjdk-devel~1.8.0.131~26.3", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-openjdk-headless", rpm:"java-1_8_0-openjdk-headless~1.8.0.131~26.3", rls:"SLES12.0SP2"))) {
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
