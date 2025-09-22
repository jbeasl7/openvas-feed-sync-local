# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2025.02657.1");
  script_cve_id("CVE-2025-30749", "CVE-2025-30754", "CVE-2025-50059", "CVE-2025-50106");
  script_tag(name:"creation_date", value:"2025-08-06 04:27:26 +0000 (Wed, 06 Aug 2025)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-07-15 20:15:40 +0000 (Tue, 15 Jul 2025)");

  script_name("SUSE: Security Advisory (SUSE-SU-2025:02657-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP6)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:02657-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-202502657-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1213796");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1246575");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1246584");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1246595");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1246598");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-updates/2025-August/041063.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'java-21-openjdk' package(s) announced via the SUSE-SU-2025:02657-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"- CVE-2025-30749: several scenarios can lead to heap corruption (bsc#1246595)
- CVE-2025-30754: incomplete handshake may lead to weakening TLS protections (bsc#1246598)
- CVE-2025-50059: Improve HTTP client header handling (bsc#1246575)
- CVE-2025-50106: Glyph out-of-memory access and crash (bsc#1246584)

Other fixes:

- Allow compilation of openjdk for 40 years (bsc#1213796)

Changelog:

 + JDK-6956385: URLConnection.getLastModified() leaks file
 handles for jar:file and file: URLs
 + JDK-8051591: Test
 javax/swing/JTabbedPane/8007563/Test8007563.java fails
 + JDK-8136895: Writer not closed with disk full error, file
 resource leaked
 + JDK-8180450: secondary_super_cache does not scale well
 + JDK-8183348: Better cleanup for
 jdk/test/sun/security/pkcs12/P12SecretKey.java
 + JDK-8200566: DistributionPointFetcher fails to fetch CRLs if
 the DistributionPoints field contains more than one
 DistributionPoint and the first one fails
 + JDK-8202100: Merge vm/share/InMemoryJavaCompiler w/
 jdk/test/lib/compiler/InMemoryJavaCompiler
 + JDK-8210471: GZIPInputStream constructor could leak an
 un-end()ed Inflater
 + JDK-8211400: nsk.share.gc.Memory::getArrayLength returns
 wrong value
 + JDK-8220213: com/sun/jndi/dns/ConfigTests/Timeout.java
 failed intermittent
 + JDK-8249831: Test sun/security/mscapi/nonUniqueAliases/
 /NonUniqueAliases.java is marked with @ignore
 + JDK-8253440: serviceability/sa/TestJhsdbJstackLineNumbers.java
 failed with 'Didn't find enough line numbers'
 + JDK-8256211: assert fired in
 java/net/httpclient/DependentPromiseActionsTest (infrequent)
 + JDK-8258483: [TESTBUG] gtest
 CollectorPolicy.young_scaled_initial_ergo_vm fails if heap is
 too small
 + JDK-8267174: Many test files have the wrong Copyright header
 + JDK-8270269: Desktop.browse method fails if earlier
 CoInitialize call as COINIT_MULTITHREADED
 + JDK-8276995: Bug in jdk.jfr.event.gc.collection.TestSystemGC
 + JDK-8279016: JFR Leak Profiler is broken with Shenandoah
 + JDK-8280991: [XWayland] No displayChanged event after
 setDisplayMode call
 + JDK-8281511: java/net/ipv6tests/UdpTest.java fails with
 checkTime failed
 + JDK-8282726: java/net/vthread/BlockingSocketOps.java
 timeout/hang intermittently on Windows
 + JDK-8286204: [Accessibility,macOS,VoiceOver] VoiceOver reads
 the spinner value 10 as 1 when user iterates to 10 for the
 first time on macOS
 + JDK-8286789: Test forceEarlyReturn002.java timed out
 + JDK-8286875: ProgrammableUpcallHandler::on_entry/on_exit
 access thread fields from native
 + JDK-8294155: Exception thrown before awaitAndCheck hangs
 PassFailJFrame
 + JDK-8295804: javax/swing/JFileChooser/
 /JFileChooserSetLocationTest.java failed with 'setLocation()
 is not working properly'
 + JDK-8297692: Avoid sending per-region GCPhaseParallel JFR
 events in G1ScanCollectionSetRegionClosure
 + JDK-8303770: Remove Baltimore root certificate expiring in
 May 2025
 + JDK-8305010: ... [Please see the references for more information on the vulnerabilities]");

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

  if(!isnull(res = isrpmvuln(pkg:"java-21-openjdk", rpm:"java-21-openjdk~21.0.8.0~150600.3.15.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-21-openjdk-demo", rpm:"java-21-openjdk-demo~21.0.8.0~150600.3.15.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-21-openjdk-devel", rpm:"java-21-openjdk-devel~21.0.8.0~150600.3.15.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-21-openjdk-headless", rpm:"java-21-openjdk-headless~21.0.8.0~150600.3.15.1", rls:"SLES15.0SP6"))) {
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
