# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2025.1524.1");
  script_cve_id("CVE-2025-21587", "CVE-2025-30691", "CVE-2025-30698");
  script_tag(name:"creation_date", value:"2025-05-12 04:09:48 +0000 (Mon, 12 May 2025)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-04-15 21:15:54 +0000 (Tue, 15 Apr 2025)");

  script_name("SUSE: Security Advisory (SUSE-SU-2025:1524-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:1524-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-20251524-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1241274");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1241275");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1241276");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-updates/2025-May/039194.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'java-1_8_0-openjdk' package(s) announced via the SUSE-SU-2025:1524-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for java-1_8_0-openjdk fixes the following issues:

Update to version jdk8u452 (icedtea-3.35.0)

Security issues fixed:

- CVE-2025-21587: unauthorized creation, deletion or modification of critical data through the JSSE component.
 (bsc#1241274)
- CVE-2025-30691: unauthorized update, insert or delete access to a subset of Oracle Java SE data through the Compiler
 component. (bsc#1241275)
- CVE-2025-30698: unauthorized access to Oracle Java SE data and unauthorized ability to cause partial DoS through the
 2D component. (bsc#1241276)

Non-security issues fixed:

- JDK-8212096: javax/net/ssl/ServerName/SSLEngineExplorerMatchedSNI.java failed intermittently due to SSLException:
 Tag mismatch.
- JDK-8261020: wrong format parameter in create_emergency_chunk_path.
- JDK-8266881: enable debug log for SSLEngineExplorerMatchedSNI.java.
- JDK-8268457: XML Transformer outputs Unicode supplementary character incorrectly to HTML.
- JDK-8309841: Jarsigner should print a warning if an entry is removed.
- JDK-8337494: clarify JarInputStream behavior.
- JDK-8339637: (tz) update Timezone Data to 2024b.
- JDK-8339644: improve parsing of Day/Month in tzdata rules
- JDK-8339810: clean up the code in sun.tools.jar.Main to properly close resources and use ZipFile during extract.
- JDK-8340552: harden TzdbZoneRulesCompiler against missing zone names.
- JDK-8342562: enhance Deflater operations.
- JDK-8346587: distrust TLS server certificates anchored by Camerfirma Root CAs.
- JDK-8347847: enhance jar file support.
- JDK-8347965: (tz) update Timezone Data to 2025a.
- JDK-8348211: [8u] sun/management/jmxremote/startstop/JMXStartStopTest.java fails after backport of JDK-8066708.
- JDK-8350816: [8u] update TzdbZoneRulesCompiler to ignore HST/EST/MST links.
- JDK-8352097: (tz) zone.tab update missed in 2025a backport.
- JDK-8353433: XCG currency code not recognized in JDK 8u.");

  script_tag(name:"affected", value:"'java-1_8_0-openjdk' package(s) on SUSE Linux Enterprise Server 12-SP5.");

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

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-openjdk", rpm:"java-1_8_0-openjdk~1.8.0.452~27.114.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-openjdk-demo", rpm:"java-1_8_0-openjdk-demo~1.8.0.452~27.114.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-openjdk-devel", rpm:"java-1_8_0-openjdk-devel~1.8.0.452~27.114.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-openjdk-headless", rpm:"java-1_8_0-openjdk-headless~1.8.0.452~27.114.1", rls:"SLES12.0SP5"))) {
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
