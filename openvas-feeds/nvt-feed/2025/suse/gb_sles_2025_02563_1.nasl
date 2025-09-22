# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2025.02563.1");
  script_cve_id("CVE-2025-30749", "CVE-2025-30754", "CVE-2025-30761", "CVE-2025-50059", "CVE-2025-50106");
  script_tag(name:"creation_date", value:"2025-08-01 04:33:06 +0000 (Fri, 01 Aug 2025)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-07-15 20:15:40 +0000 (Tue, 15 Jul 2025)");

  script_name("SUSE: Security Advisory (SUSE-SU-2025:02563-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:02563-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-202502563-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1246575");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1246580");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1246584");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1246595");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1246598");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-updates/2025-July/040972.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'java-11-openjdk' package(s) announced via the SUSE-SU-2025:02563-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"- CVE-2025-30749: several scenarios can lead to heap corruption (bsc#1246595)
- CVE-2025-30754: incomplete handshake may lead to weakening TLS protections (bsc#1246598)
- CVE-2025-30761: Improve scripting supports (bsc#1246580)
- CVE-2025-50059: Improve HTTP client header handling (bsc#1246575)
- CVE-2025-50106: Glyph out-of-memory access and crash (bsc#1246584)

Changelog:

 + JDK-8026976: ECParameters, Point does not match field size
 + JDK-8211400: nsk.share.gc.Memory::getArrayLength returns wrong
 value
 + JDK-8231058: VerifyOops crashes with assert(_offset >= 0)
 failed: offset for non comment?
 + JDK-8232625: HttpClient redirect policy should be more
 conservative
 + JDK-8258483: [TESTBUG] gtest
 CollectorPolicy.young_scaled_initial_ergo_vm fails if heap is
 too small
 + JDK-8293345: SunPKCS11 provider checks on PKCS11 Mechanism are
 problematic
 + JDK-8296631: NSS tests failing on OL9 linux-aarch64 hosts
 + JDK-8301753: AppendFile/WriteFile has differences between make
 3.81 and 4+
 + JDK-8303770: Remove Baltimore root certificate expiring in May
 2025
 + JDK-8315380: AsyncGetCallTrace crash in frame::safe_for_sender
 + JDK-8327476: Upgrade JLine to 3.26.1
 + JDK-8328957: Update PKCS11Test.java to not use hardcoded path
 + JDK-8331959: Update PKCS#11 Cryptographic Token Interface to
 v3.1
 + JDK-8339300: CollectorPolicy.young_scaled_initial_ergo_vm
 gtest fails on ppc64 based platforms
 + JDK-8339728: [Accessibility,Windows,JAWS] Bug in the
 getKeyChar method of the AccessBridge class
 + JDK-8345133: Test sun/security/tools/jarsigner/
 /TsacertOptionTest.java failed: Warning found in stdout
 + JDK-8345625: Better HTTP connections
 + JDK-8346887: DrawFocusRect() may cause an assertion failure
 + JDK-8347629: Test FailOverDirectExecutionControlTest.java
 fails with -Xcomp
 + JDK-8348110: Update LCMS to 2.17
 + JDK-8348596: Update FreeType to 2.13.3
 + JDK-8348598: Update Libpng to 1.6.47
 + JDK-8348989: Better Glyph drawing
 + JDK-8349111: Enhance Swing supports
 + JDK-8349594: Enhance TLS protocol support
 + JDK-8350469: [11u] Test AbsPathsInImage.java fails
 - JDK-8239429 public clone
 + JDK-8350498: Remove two Camerfirma root CA certificates
 + JDK-8350991: Improve HTTP client header handling
 + JDK-8351099: Bump update version of OpenJDK: 11.0.28
 + JDK-8351422: Improve scripting supports
 + JDK-8352302: Test sun/security/tools/jarsigner/
 /TimestampCheck.java is failing
 + JDK-8352716: (tz) Update Timezone Data to 2025b
 + JDK-8356096: ISO 4217 Amendment 179 Update
 + JDK-8356571: Re-enable -Wtype-limits for GCC in LCMS
 + JDK-8359170: Add 2 TLS and 2 CS Sectigo roots
 + JDK-8360147: Better Glyph drawing redux");

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

  if(!isnull(res = isrpmvuln(pkg:"java-11-openjdk", rpm:"java-11-openjdk~11.0.28.0~3.90.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-11-openjdk-demo", rpm:"java-11-openjdk-demo~11.0.28.0~3.90.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-11-openjdk-devel", rpm:"java-11-openjdk-devel~11.0.28.0~3.90.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-11-openjdk-headless", rpm:"java-11-openjdk-headless~11.0.28.0~3.90.1", rls:"SLES12.0SP5"))) {
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
