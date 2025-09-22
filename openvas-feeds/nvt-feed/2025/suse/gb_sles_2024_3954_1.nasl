# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2024.3954.1");
  script_cve_id("CVE-2024-21208", "CVE-2024-21210", "CVE-2024-21217", "CVE-2024-21235");
  script_tag(name:"creation_date", value:"2025-06-04 14:43:37 +0000 (Wed, 04 Jun 2025)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-10-15 20:15:12 +0000 (Tue, 15 Oct 2024)");

  script_name("SUSE: Security Advisory (SUSE-SU-2024:3954-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP6)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:3954-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2024/suse-su-20243954-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231702");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231711");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231716");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231719");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2024-November/019802.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'java-21-openjdk' package(s) announced via the SUSE-SU-2024:3954-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for java-21-openjdk fixes the following issues:

- Update to upstream tag jdk-21.0.5+13 (October 2024 CPU)
 * Security fixes
 + JDK-8307383: Enhance DTLS connections
 + JDK-8311208: Improve CDS Support
 + JDK-8328286, CVE-2024-21208, bsc#1231702: Enhance HTTP client
 + JDK-8328544, CVE-2024-21210, bsc#1231711: Improve handling of vectorization
 + JDK-8328726: Better Kerberos support
 + JDK-8331446, CVE-2024-21217, bsc#1231716: Improve deserialization support
 + JDK-8332644, CVE-2024-21235, bsc#1231719: Improve graph optimizations
 + JDK-8335713: Enhance vectorization analysis
 * Other changes
 + JDK-6355567: AdobeMarkerSegment causes failure to read valid JPEG
 + JDK-6967482: TAB-key does not work in JTables after selecting
 details-view in JFileChooser
 + JDK-7022325: TEST_BUG: test/java/util/zip/ZipFile/
 /ReadLongZipFileName.java leaks files if it fails
 + JDK-8051959: Add thread and timestamp options to
 java.security.debug system property
 + JDK-8073061: (fs) Files.copy(foo, bar, REPLACE_EXISTING)
 deletes bar even if foo is not readable
 + JDK-8166352: FilePane.createDetailsView() removes JTable TAB,
 SHIFT-TAB functionality
 + JDK-8170817: G1: Returning MinTLABSize from
 unsafe_max_tlab_alloc causes TLAB flapping
 + JDK-8211847: [aix] java/lang/ProcessHandle/InfoTest.java
 fails: 'reported cputime less than expected'
 + JDK-8211854: [aix] java/net/ServerSocket/
 /AcceptInheritHandle.java fails: read times out
 + JDK-8222884: ConcurrentClassDescLookup.java times out intermittently
 + JDK-8238169: BasicDirectoryModel getDirectories and
 DoChangeContents.run can deadlock
 + JDK-8241550: [macOS] SSLSocketImpl/ReuseAddr.java failed due
 to 'BindException: Address already in use'
 + JDK-8242564: javadoc crashes:: class cast exception
 com.sun.tools.javac.code.Symtab$6
 + JDK-8260633: [macos] java/awt/dnd/MouseEventAfterStartDragTest/
 /MouseEventAfterStartDragTest.html test failed
 + JDK-8261433: Better pkcs11 performance for
 libpkcs11:C_EncryptInit/libpkcs11:C_DecryptInit
 + JDK-8269428: java/util/concurrent/ConcurrentHashMap/
 /ToArray.java timed out
 + JDK-8269657: Test java/nio/channels/DatagramChannel/
 /Loopback.java failed: Unexpected message
 + JDK-8280120: [IR Framework] Add attribute to @IR to
 enable/disable IR matching based on the architecture
 + JDK-8280392: java/awt/Focus/NonFocusableWindowTest/
 /NonfocusableOwnerTest.java failed with 'RuntimeException: Test failed.'
 + JDK-8280988: [XWayland] Click on title to request focus test failures
 + JDK-8280990: [XWayland] XTest emulated mouse click does not
 bring window to front
 + JDK-8283223: gc/stringdedup/TestStringDeduplicationFullGC.java
 #Parallel failed with 'RuntimeException: String verification failed'
 + JDK-8287325: AArch64: fix virtual threads with
 -XX:UseBranchProtection=pac-ret
 + JDK-8291809: Convert compiler/c2/cr7200264/TestSSE2IntVect.java
 to IR verification test
 + ... [Please see the references for more information on the vulnerabilities]");

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

  if(!isnull(res = isrpmvuln(pkg:"java-21-openjdk", rpm:"java-21-openjdk~21.0.5.0~150600.3.6.3", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-21-openjdk-demo", rpm:"java-21-openjdk-demo~21.0.5.0~150600.3.6.3", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-21-openjdk-devel", rpm:"java-21-openjdk-devel~21.0.5.0~150600.3.6.3", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-21-openjdk-headless", rpm:"java-21-openjdk-headless~21.0.5.0~150600.3.6.3", rls:"SLES15.0SP6"))) {
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
