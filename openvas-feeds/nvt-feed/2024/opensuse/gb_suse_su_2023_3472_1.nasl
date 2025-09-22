# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833248");
  script_version("2025-02-26T05:38:41+0000");
  script_cve_id("CVE-2023-4016");
  script_tag(name:"cvss_base", value:"1.7");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:L");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-12-15 18:19:03 +0000 (Fri, 15 Dec 2023)");
  script_tag(name:"creation_date", value:"2024-03-04 07:44:22 +0000 (Mon, 04 Mar 2024)");
  script_name("openSUSE: Security Advisory for procps (SUSE-SU-2023:3472-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=(openSUSELeap15\.4|openSUSELeap15\.5|openSUSELeapMicro5\.3|openSUSELeapMicro5\.4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:3472-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/7S2PM2GUC6J3VSY77LYZFPJ2HG5YPJI7");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'procps'
  package(s) announced via the SUSE-SU-2023:3472-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for procps fixes the following issues:

  * CVE-2023-4016: Fixed ps buffer overflow (bsc#1214290).

  ##");

  script_tag(name:"affected", value:"'procps' package(s) on openSUSE Leap 15.4, openSUSE Leap 15.5, openSUSE Leap Micro 5.3, openSUSE Leap Micro 5.4.");

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

  if(!isnull(res = isrpmvuln(pkg:"libprocps7", rpm:"libprocps7~3.3.15~150000.7.34.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"procps-debuginfo", rpm:"procps-debuginfo~3.3.15~150000.7.34.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"procps-devel", rpm:"procps-devel~3.3.15~150000.7.34.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libprocps7-debuginfo", rpm:"libprocps7-debuginfo~3.3.15~150000.7.34.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"procps", rpm:"procps~3.3.15~150000.7.34.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"procps-debugsource", rpm:"procps-debugsource~3.3.15~150000.7.34.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libprocps7", rpm:"libprocps7~3.3.15~150000.7.34.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"procps-debuginfo", rpm:"procps-debuginfo~3.3.15~150000.7.34.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"procps-devel", rpm:"procps-devel~3.3.15~150000.7.34.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libprocps7-debuginfo", rpm:"libprocps7-debuginfo~3.3.15~150000.7.34.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"procps", rpm:"procps~3.3.15~150000.7.34.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"procps-debugsource", rpm:"procps-debugsource~3.3.15~150000.7.34.1", rls:"openSUSELeap15.4"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"libprocps7", rpm:"libprocps7~3.3.15~150000.7.34.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"procps-debuginfo", rpm:"procps-debuginfo~3.3.15~150000.7.34.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"procps-devel", rpm:"procps-devel~3.3.15~150000.7.34.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libprocps7-debuginfo", rpm:"libprocps7-debuginfo~3.3.15~150000.7.34.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"procps", rpm:"procps~3.3.15~150000.7.34.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"procps-debugsource", rpm:"procps-debugsource~3.3.15~150000.7.34.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libprocps7", rpm:"libprocps7~3.3.15~150000.7.34.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"procps-debuginfo", rpm:"procps-debuginfo~3.3.15~150000.7.34.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"procps-devel", rpm:"procps-devel~3.3.15~150000.7.34.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libprocps7-debuginfo", rpm:"libprocps7-debuginfo~3.3.15~150000.7.34.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"procps", rpm:"procps~3.3.15~150000.7.34.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"procps-debugsource", rpm:"procps-debugsource~3.3.15~150000.7.34.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "openSUSELeapMicro5.3") {

  if(!isnull(res = isrpmvuln(pkg:"libprocps7", rpm:"libprocps7~3.3.15~150000.7.34.1", rls:"openSUSELeapMicro5.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"procps-debuginfo", rpm:"procps-debuginfo~3.3.15~150000.7.34.1", rls:"openSUSELeapMicro5.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libprocps7-debuginfo", rpm:"libprocps7-debuginfo~3.3.15~150000.7.34.1", rls:"openSUSELeapMicro5.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"procps", rpm:"procps~3.3.15~150000.7.34.1", rls:"openSUSELeapMicro5.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"procps-debugsource", rpm:"procps-debugsource~3.3.15~150000.7.34.1", rls:"openSUSELeapMicro5.3"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "openSUSELeapMicro5.4") {

  if(!isnull(res = isrpmvuln(pkg:"libprocps7", rpm:"libprocps7~3.3.15~150000.7.34.1", rls:"openSUSELeapMicro5.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"procps-debuginfo", rpm:"procps-debuginfo~3.3.15~150000.7.34.1", rls:"openSUSELeapMicro5.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libprocps7-debuginfo", rpm:"libprocps7-debuginfo~3.3.15~150000.7.34.1", rls:"openSUSELeapMicro5.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"procps", rpm:"procps~3.3.15~150000.7.34.1", rls:"openSUSELeapMicro5.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"procps-debugsource", rpm:"procps-debugsource~3.3.15~150000.7.34.1", rls:"openSUSELeapMicro5.4"))) {
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