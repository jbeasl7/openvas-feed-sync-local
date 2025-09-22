# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833277");
  script_version("2025-02-26T05:38:41+0000");
  script_cve_id("CVE-2022-40609", "CVE-2023-22006", "CVE-2023-22036", "CVE-2023-22041", "CVE-2023-22044", "CVE-2023-22045", "CVE-2023-22049", "CVE-2023-25193");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-08-07 16:10:23 +0000 (Mon, 07 Aug 2023)");
  script_tag(name:"creation_date", value:"2024-03-04 07:56:43 +0000 (Mon, 04 Mar 2024)");
  script_name("openSUSE: Security Advisory for java (SUSE-SU-2023:3441-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=(openSUSELeap15\.4|openSUSELeap15\.5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:3441-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/MRJGVOWO5JZRA67F6PZK4EOZD33KHEAM");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'java'
  package(s) announced via the SUSE-SU-2023:3441-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for java-1_8_0-ibm fixes the following issues:

  * Update to Java 8.0 Service Refresh 8 Fix Pack 10 (bsc#1213541)

  * CVE-2022-40609: Fixed an unsafe deserialization flaw which could allow a
      remote attacker to execute arbitrary code on the system. (bsc#1213934)

  * CVE-2023-22041: Fixed a flaw which could allow unauthorized access to
      critical data or complete access. (bsc#1213475)

  * CVE-2023-22049: Fixed a flaw which could result in unauthorized update.
      (bsc#1213482)

  * CVE-2023-22045: Fixed a flaw which could result in unauthorized read access
      to a subset of Oracle Java SE, Oracle GraalVM Enterprise Edition, Oracle
      GraalVM for JDK accessible data. (bsc#1213481)

  * CVE-2023-22044: Fixed a flaw which could result in unauthorized read access
      to a subset of Oracle Java SE, Oracle GraalVM Enterprise Edition, Oracle
      GraalVM for JDK accessible data. (bsc#1213479)

  * CVE-2023-22036: Fixed a flaw which could result in unauthorized ability to
      cause a partial denial of service. (bsc#1213474)

  * CVE-2023-25193: Fixed a flaw which could allows attackers to trigger O(n^2)
      growth via consecutive marks during the process of looking back for base
      glyphs when attaching marks. (bsc#1207922)

  * CVE-2023-22006: Fixed a flaw which could result in unauthorized update,
      insert or delete access for JDK accessible data. (bsc#1213473)

  ##");

  script_tag(name:"affected", value:"'java' package(s) on openSUSE Leap 15.4, openSUSE Leap 15.5.");

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

if(release == "openSUSELeap15.4") {

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-ibm", rpm:"java-1_8_0-ibm~1.8.0_sr8.10~150000.3.80.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-ibm-plugin", rpm:"java-1_8_0-ibm-plugin~1.8.0_sr8.10~150000.3.80.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-ibm-devel-32bit", rpm:"java-1_8_0-ibm-devel-32bit~1.8.0_sr8.10~150000.3.80.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-ibm-alsa", rpm:"java-1_8_0-ibm-alsa~1.8.0_sr8.10~150000.3.80.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-ibm-32bit", rpm:"java-1_8_0-ibm-32bit~1.8.0_sr8.10~150000.3.80.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-ibm-demo", rpm:"java-1_8_0-ibm-demo~1.8.0_sr8.10~150000.3.80.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-ibm-devel", rpm:"java-1_8_0-ibm-devel~1.8.0_sr8.10~150000.3.80.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-ibm-src", rpm:"java-1_8_0-ibm-src~1.8.0_sr8.10~150000.3.80.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-ibm", rpm:"java-1_8_0-ibm~1.8.0_sr8.10~150000.3.80.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-ibm-plugin", rpm:"java-1_8_0-ibm-plugin~1.8.0_sr8.10~150000.3.80.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-ibm-devel-32bit", rpm:"java-1_8_0-ibm-devel-32bit~1.8.0_sr8.10~150000.3.80.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-ibm-alsa", rpm:"java-1_8_0-ibm-alsa~1.8.0_sr8.10~150000.3.80.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-ibm-32bit", rpm:"java-1_8_0-ibm-32bit~1.8.0_sr8.10~150000.3.80.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-ibm-demo", rpm:"java-1_8_0-ibm-demo~1.8.0_sr8.10~150000.3.80.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-ibm-devel", rpm:"java-1_8_0-ibm-devel~1.8.0_sr8.10~150000.3.80.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-ibm-src", rpm:"java-1_8_0-ibm-src~1.8.0_sr8.10~150000.3.80.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "openSUSELeap15.5") {

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-ibm", rpm:"java-1_8_0-ibm~1.8.0_sr8.10~150000.3.80.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-ibm-plugin", rpm:"java-1_8_0-ibm-plugin~1.8.0_sr8.10~150000.3.80.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-ibm-devel-32bit", rpm:"java-1_8_0-ibm-devel-32bit~1.8.0_sr8.10~150000.3.80.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-ibm-alsa", rpm:"java-1_8_0-ibm-alsa~1.8.0_sr8.10~150000.3.80.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-ibm-32bit", rpm:"java-1_8_0-ibm-32bit~1.8.0_sr8.10~150000.3.80.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-ibm-demo", rpm:"java-1_8_0-ibm-demo~1.8.0_sr8.10~150000.3.80.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-ibm-devel", rpm:"java-1_8_0-ibm-devel~1.8.0_sr8.10~150000.3.80.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-ibm-src", rpm:"java-1_8_0-ibm-src~1.8.0_sr8.10~150000.3.80.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-ibm", rpm:"java-1_8_0-ibm~1.8.0_sr8.10~150000.3.80.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-ibm-plugin", rpm:"java-1_8_0-ibm-plugin~1.8.0_sr8.10~150000.3.80.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-ibm-devel-32bit", rpm:"java-1_8_0-ibm-devel-32bit~1.8.0_sr8.10~150000.3.80.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-ibm-alsa", rpm:"java-1_8_0-ibm-alsa~1.8.0_sr8.10~150000.3.80.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-ibm-32bit", rpm:"java-1_8_0-ibm-32bit~1.8.0_sr8.10~150000.3.80.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-ibm-demo", rpm:"java-1_8_0-ibm-demo~1.8.0_sr8.10~150000.3.80.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-ibm-devel", rpm:"java-1_8_0-ibm-devel~1.8.0_sr8.10~150000.3.80.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-ibm-src", rpm:"java-1_8_0-ibm-src~1.8.0_sr8.10~150000.3.80.1", rls:"openSUSELeap15.5"))) {
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