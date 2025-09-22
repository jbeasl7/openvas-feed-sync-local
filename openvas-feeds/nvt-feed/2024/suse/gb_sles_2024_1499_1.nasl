# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2024.1499.1");
  script_cve_id("CVE-2024-21011", "CVE-2024-21012", "CVE-2024-21068", "CVE-2024-21094");
  script_tag(name:"creation_date", value:"2024-05-07 13:39:54 +0000 (Tue, 07 May 2024)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"2.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-04-16 22:15:29 +0000 (Tue, 16 Apr 2024)");

  script_name("SUSE: Security Advisory (SUSE-SU-2024:1499-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:1499-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2024/suse-su-20241499-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1213470");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222979");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222983");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222986");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222987");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2024-May/018448.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'java-17-openjdk' package(s) announced via the SUSE-SU-2024:1499-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for java-17-openjdk fixes the following issues:

- CVE-2024-21011: Fixed denial of service due to long Exception message logging (JDK-8319851,bsc#1222979)
- CVE-2024-21012: Fixed unauthorized data modification due HTTP/2 client improper reverse DNS lookup (JDK-8315708,bsc#1222987)
- CVE-2024-21068: Fixed integer overflow in C1 compiler address generation (JDK-8322122,bsc#1222983)
- CVE-2024-21094: Fixed unauthorized data modification due to C2 compilation failure with 'Exceeded _node_regs array' (JDK-8317507,JDK-8325348,bsc#1222986)

Other fixes:
- Update to upstream tag jdk-17.0.11+9 (April 2024 CPU)
 * Security fixes
 + JDK-8318340: Improve RSA key implementations
 * Other changes
 + JDK-6928542: Chinese characters in RTF are not decoded
 + JDK-7132796: [macosx] closed/javax/swing/JComboBox/4517214/
 /bug4517214.java fails on MacOS
 + JDK-7148092: [macosx] When Alt+down arrow key is pressed, the
 combobox popup does not appear.
 + JDK-7167356: (javac) investigate failing tests in
 JavacParserTest
 + JDK-8054022: HttpURLConnection timeouts with Expect:
 100-Continue and no chunking
 + JDK-8054572: [macosx] JComboBox paints the border incorrectly
 + JDK-8169475: WheelModifier.java fails by timeout
 + JDK-8205076: [17u] Inet6AddressImpl.c: `lookupIfLocalHost`
 accesses `int InetAddress.preferIPv6Address` as a boolean
 + JDK-8209595: MonitorVmStartTerminate.java timed out
 + JDK-8210410: Refactor java.util.Currency:i18n shell tests to
 plain java tests
 + JDK-8261404: Class.getReflectionFactory() is not thread-safe
 + JDK-8261837: SIGSEGV in ciVirtualCallTypeData::translate_from
 + JDK-8263256: Test java/net/Inet6Address/serialize/
 /Inet6AddressSerializationTest.java fails due to dynamic
 reconfigurations of network interface during test
 + JDK-8269258: java/net/httpclient/ManyRequestsLegacy.java
 failed with connection timeout
 + JDK-8271118: C2: StressGCM should have higher priority than
 frequency-based policy
 + JDK-8271616: oddPart in MutableBigInteger::mutableModInverse
 contains info on final result
 + JDK-8272811: Document the effects of building with
 _GNU_SOURCE in os_posix.hpp
 + JDK-8272853: improve `JavadocTester.runTests`
 + JDK-8273454: C2: Transform (-a)*(-b) into a*b
 + JDK-8274060: C2: Incorrect computation after JDK-8273454
 + JDK-8274122: java/io/File/createTempFile/SpecialTempFile.java
 fails in Windows 11
 + JDK-8274621: NullPointerException because listenAddress[0] is
 null
 + JDK-8274632: Possible pointer overflow in PretouchTask chunk
 claiming
 + JDK-8274634: Use String.equals instead of String.compareTo in
 java.desktop
 + JDK-8276125: RunThese24H.java SIGSEGV in
 JfrThreadGroup::thread_group_id
 + JDK-8278028: [test-library] Warnings cleanup of the test
 library
 + JDK-8278312: Update SimpleSSLContext keystore to use SANs for
 localhost IP addresses
 + JDK-8278363: Create extented container test groups
 + JDK-8280241: (aio) ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'java-17-openjdk' package(s) on SUSE Linux Enterprise Server 15-SP4, SUSE Linux Enterprise Server for SAP Applications 15-SP4.");

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

  if(!isnull(res = isrpmvuln(pkg:"java-17-openjdk", rpm:"java-17-openjdk~17.0.11.0~150400.3.42.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-17-openjdk-demo", rpm:"java-17-openjdk-demo~17.0.11.0~150400.3.42.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-17-openjdk-devel", rpm:"java-17-openjdk-devel~17.0.11.0~150400.3.42.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-17-openjdk-headless", rpm:"java-17-openjdk-headless~17.0.11.0~150400.3.42.1", rls:"SLES15.0SP4"))) {
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
