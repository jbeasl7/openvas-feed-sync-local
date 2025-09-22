# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833853");
  script_version("2025-02-26T05:38:41+0000");
  script_cve_id("CVE-2023-21835", "CVE-2023-21843");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-01-18 00:15:13 +0000 (Wed, 18 Jan 2023)");
  script_tag(name:"creation_date", value:"2024-03-04 07:57:16 +0000 (Mon, 04 Mar 2024)");
  script_name("openSUSE: Security Advisory for java (SUSE-SU-2023:0435-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.4");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:0435-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/ZA2W3Z5S6AZIZWHI62CMMBXZ6FDENTYY");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'java'
  package(s) announced via the SUSE-SU-2023:0435-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for java-17-openjdk fixes the following issues:

       Updated to version jdk-17.0.6.0+10:

  - CVE-2023-21835: Fixed handshake DoS attack against DTLS connections
         (bsc#1207246).

  - CVE-2023-21843: Fixed soundbank URL remote loading (bsc#1207248).

       Bugfixes:

  - Avoid calling C_GetInfo() too early, before cryptoki is initialized
         (bsc#1205916).");

  script_tag(name:"affected", value:"'java' package(s) on openSUSE Leap 15.4.");

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

  if(!isnull(res = isrpmvuln(pkg:"java-17-openjdk", rpm:"java-17-openjdk~17.0.6.0~150400.3.12.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-17-openjdk-accessibility", rpm:"java-17-openjdk-accessibility~17.0.6.0~150400.3.12.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-17-openjdk-accessibility-debuginfo", rpm:"java-17-openjdk-accessibility-debuginfo~17.0.6.0~150400.3.12.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-17-openjdk-debuginfo", rpm:"java-17-openjdk-debuginfo~17.0.6.0~150400.3.12.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-17-openjdk-debugsource", rpm:"java-17-openjdk-debugsource~17.0.6.0~150400.3.12.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-17-openjdk-demo", rpm:"java-17-openjdk-demo~17.0.6.0~150400.3.12.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-17-openjdk-devel", rpm:"java-17-openjdk-devel~17.0.6.0~150400.3.12.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-17-openjdk-devel-debuginfo", rpm:"java-17-openjdk-devel-debuginfo~17.0.6.0~150400.3.12.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-17-openjdk-headless", rpm:"java-17-openjdk-headless~17.0.6.0~150400.3.12.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-17-openjdk-headless-debuginfo", rpm:"java-17-openjdk-headless-debuginfo~17.0.6.0~150400.3.12.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-17-openjdk-jmods", rpm:"java-17-openjdk-jmods~17.0.6.0~150400.3.12.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-17-openjdk-src", rpm:"java-17-openjdk-src~17.0.6.0~150400.3.12.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-17-openjdk-javadoc", rpm:"java-17-openjdk-javadoc~17.0.6.0~150400.3.12.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-17-openjdk", rpm:"java-17-openjdk~17.0.6.0~150400.3.12.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-17-openjdk-accessibility", rpm:"java-17-openjdk-accessibility~17.0.6.0~150400.3.12.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-17-openjdk-accessibility-debuginfo", rpm:"java-17-openjdk-accessibility-debuginfo~17.0.6.0~150400.3.12.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-17-openjdk-debuginfo", rpm:"java-17-openjdk-debuginfo~17.0.6.0~150400.3.12.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-17-openjdk-debugsource", rpm:"java-17-openjdk-debugsource~17.0.6.0~150400.3.12.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-17-openjdk-demo", rpm:"java-17-openjdk-demo~17.0.6.0~150400.3.12.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-17-openjdk-devel", rpm:"java-17-openjdk-devel~17.0.6.0~150400.3.12.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-17-openjdk-devel-debuginfo", rpm:"java-17-openjdk-devel-debuginfo~17.0.6.0~150400.3.12.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-17-openjdk-headless", rpm:"java-17-openjdk-headless~17.0.6.0~150400.3.12.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-17-openjdk-headless-debuginfo", rpm:"java-17-openjdk-headless-debuginfo~17.0.6.0~150400.3.12.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-17-openjdk-jmods", rpm:"java-17-openjdk-jmods~17.0.6.0~150400.3.12.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-17-openjdk-src", rpm:"java-17-openjdk-src~17.0.6.0~150400.3.12.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-17-openjdk-javadoc", rpm:"java-17-openjdk-javadoc~17.0.6.0~150400.3.12.1", rls:"openSUSELeap15.4"))) {
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