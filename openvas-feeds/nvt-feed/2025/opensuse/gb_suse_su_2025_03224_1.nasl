# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.18.2.2025.03224.1");
  script_cve_id("CVE-2025-30749", "CVE-2025-30754", "CVE-2025-30761", "CVE-2025-50106");
  script_tag(name:"creation_date", value:"2025-09-17 04:06:46 +0000 (Wed, 17 Sep 2025)");
  script_version("2025-09-17T05:39:26+0000");
  script_tag(name:"last_modification", value:"2025-09-17 05:39:26 +0000 (Wed, 17 Sep 2025)");
  script_tag(name:"cvss_base", value:"7.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-07-15 20:15:47 +0000 (Tue, 15 Jul 2025)");

  script_name("openSUSE Security Advisory (SUSE-SU-2025:03224-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.6");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:03224-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-202503224-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1246580");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1246584");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1246595");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1246598");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1246806");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-updates/2025-September/041703.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'java-1_8_0-openjdk' package(s) announced via the SUSE-SU-2025:03224-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for java-1_8_0-openjdk fixes the following issues:

Update to version jdk8u462 (icedtea-3.36.0).

Security issues fixed:

- CVE-2025-30749: heap corruption allows unauthenticated attacker with network access to compromise and takeover Java
 applications that load and run untrusted code (bsc#1246595).
- CVE-2025-30754: incomplete handshake allows unauthenticated attacker with network access via TLS to gain unauthorized
 update, insert, delete and read access to sensitive data (bsc#1246598).
- CVE-2025-30761: issue in Scripting component allows unauthenticated attacker with network access to gain
 unauthorized creation, deletion or modification access to critical data (bsc#1246580).
- CVE-2025-50106: Glyph out-of-memory access allows unauthenticated attacker with network access to compromise and
 takeover Java applications that load and run untrusted code (bsc#1246584).

Other issues fixed:

- Import of OpenJDK 8 u462 build 08
 + JDK-8026976: ECParameters, Point does not match field size.
 + JDK-8071996: split_if accesses NULL region of ConstraintCast.
 + JDK-8186143: keytool -ext option doesn't accept wildcards for DNS subject alternative names.
 + JDK-8186787: clang-4.0 SIGSEGV in Unsafe_PutByte.
 + JDK-8248001: javadoc generates invalid HTML pages whose ftp:// links are broken.
 + JDK-8278472: Invalid value set to CANDIDATEFORM structure.
 + JDK-8293107: GHA: Bump to Ubuntu 22.04.
 + JDK-8303770: Remove Baltimore root certificate expiring in May 2025.
 + JDK-8309841: Jarsigner should print a warning if an entry is removed.
 + JDK-8339810: Clean up the code in sun.tools.jar.Main to properly close resources and use ZipFile during extract.
 + JDK-8345625: Better HTTP connections.
 + JDK-8346887: DrawFocusRect() may cause an assertion failure.
 + JDK-8349111: Enhance Swing supports.
 + JDK-8350498: Remove two Camerfirma root CA certificates.
 + JDK-8352716: (tz) Update Timezone Data to 2025b.
 + JDK-8353433: XCG currency code not recognized in JDK 8u.
 + JDK-8356096: ISO 4217 Amendment 179 Update.
 + JDK-8359170: Add 2 TLS and 2 CS Sectigo roots.
- Backports
 + JDK-8358538: Update GHA Windows runner to 2025.
- JDK-8354941: Build failure with glibc 2.42 due to uabs() name collision.");

  script_tag(name:"affected", value:"'java-1_8_0-openjdk' package(s) on openSUSE Leap 15.6.");

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

if(release == "openSUSELeap15.6") {

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-openjdk", rpm:"java-1_8_0-openjdk~1.8.0.462~150000.3.109.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-openjdk-accessibility", rpm:"java-1_8_0-openjdk-accessibility~1.8.0.462~150000.3.109.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-openjdk-demo", rpm:"java-1_8_0-openjdk-demo~1.8.0.462~150000.3.109.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-openjdk-devel", rpm:"java-1_8_0-openjdk-devel~1.8.0.462~150000.3.109.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-openjdk-headless", rpm:"java-1_8_0-openjdk-headless~1.8.0.462~150000.3.109.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-openjdk-javadoc", rpm:"java-1_8_0-openjdk-javadoc~1.8.0.462~150000.3.109.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-openjdk-src", rpm:"java-1_8_0-openjdk-src~1.8.0.462~150000.3.109.1", rls:"openSUSELeap15.6"))) {
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
