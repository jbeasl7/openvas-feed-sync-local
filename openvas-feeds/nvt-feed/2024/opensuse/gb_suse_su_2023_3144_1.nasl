# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833200");
  script_version("2025-02-26T05:38:41+0000");
  script_cve_id("CVE-2023-28370");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-06-01 13:04:56 +0000 (Thu, 01 Jun 2023)");
  script_tag(name:"creation_date", value:"2024-03-04 07:52:54 +0000 (Mon, 04 Mar 2024)");
  script_name("openSUSE: Security Advisory for SUSE Manager Client Tools (SUSE-SU-2023:3144-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=(openSUSELeap15\.4|openSUSELeap15\.5|openSUSELeapMicro5\.3|openSUSELeapMicro5\.4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:3144-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/MRVJ2K7ELQ5HSOQ62SX7TYHBG3D2WSXC");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'SUSE Manager Client Tools'
  package(s) announced via the SUSE-SU-2023:3144-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update fixes the following issues:

  python-tornado:

  * Security fixes:

  * CVE-2023-28370: Fixed an open redirect issue in the static file handler
      (bsc#1211741)

  prometheus-blackbox_exporter:

  * Use obscpio for go modules service

  * Set version number

  * Set build date from SOURCE_DATE_EPOCH

  * Update to 0.24.0 (bsc#1212279, jsc#PED-4556)

  * Requires go1.19

  * Avoid empty validation script

  * Add rc symlink for backwards compatibility

  spacecmd:

  * Version 4.3.22-1

  * Bypass traditional systems check on older SUMA instances (bsc#1208612)

  ##");

  script_tag(name:"affected", value:"'SUSE Manager Client Tools' package(s) on openSUSE Leap 15.4, openSUSE Leap 15.5, openSUSE Leap Micro 5.3, openSUSE Leap Micro 5.4.");

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

  if(!isnull(res = isrpmvuln(pkg:"python-tornado-debugsource", rpm:"python-tornado-debugsource~4.5.3~150000.3.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-tornado-debuginfo", rpm:"python-tornado-debuginfo~4.5.3~150000.3.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-tornado-debuginfo", rpm:"python3-tornado-debuginfo~4.5.3~150000.3.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-tornado", rpm:"python3-tornado~4.5.3~150000.3.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"prometheus-blackbox_exporter", rpm:"prometheus-blackbox_exporter~0.24.0~150000.1.20.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"spacecmd", rpm:"spacecmd~4.3.22~150000.3.101.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"system-user-prometheus", rpm:"system-user-prometheus~1.0.0~150000.10.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-tornado-debugsource", rpm:"python-tornado-debugsource~4.5.3~150000.3.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-tornado-debuginfo", rpm:"python-tornado-debuginfo~4.5.3~150000.3.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-tornado-debuginfo", rpm:"python3-tornado-debuginfo~4.5.3~150000.3.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-tornado", rpm:"python3-tornado~4.5.3~150000.3.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"prometheus-blackbox_exporter", rpm:"prometheus-blackbox_exporter~0.24.0~150000.1.20.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"spacecmd", rpm:"spacecmd~4.3.22~150000.3.101.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"system-user-prometheus", rpm:"system-user-prometheus~1.0.0~150000.10.1", rls:"openSUSELeap15.4"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"python-tornado-debugsource", rpm:"python-tornado-debugsource~4.5.3~150000.3.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-tornado-debuginfo", rpm:"python-tornado-debuginfo~4.5.3~150000.3.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-tornado-debuginfo", rpm:"python3-tornado-debuginfo~4.5.3~150000.3.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-tornado", rpm:"python3-tornado~4.5.3~150000.3.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"prometheus-blackbox_exporter", rpm:"prometheus-blackbox_exporter~0.24.0~150000.1.20.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"spacecmd", rpm:"spacecmd~4.3.22~150000.3.101.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"system-user-prometheus", rpm:"system-user-prometheus~1.0.0~150000.10.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-tornado-debugsource", rpm:"python-tornado-debugsource~4.5.3~150000.3.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-tornado-debuginfo", rpm:"python-tornado-debuginfo~4.5.3~150000.3.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-tornado-debuginfo", rpm:"python3-tornado-debuginfo~4.5.3~150000.3.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-tornado", rpm:"python3-tornado~4.5.3~150000.3.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"prometheus-blackbox_exporter", rpm:"prometheus-blackbox_exporter~0.24.0~150000.1.20.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"spacecmd", rpm:"spacecmd~4.3.22~150000.3.101.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"system-user-prometheus", rpm:"system-user-prometheus~1.0.0~150000.10.1", rls:"openSUSELeap15.5"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"python-tornado-debugsource", rpm:"python-tornado-debugsource~4.5.3~150000.3.6.1", rls:"openSUSELeapMicro5.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-tornado-debuginfo", rpm:"python-tornado-debuginfo~4.5.3~150000.3.6.1", rls:"openSUSELeapMicro5.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-tornado-debuginfo", rpm:"python3-tornado-debuginfo~4.5.3~150000.3.6.1", rls:"openSUSELeapMicro5.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-tornado", rpm:"python3-tornado~4.5.3~150000.3.6.1", rls:"openSUSELeapMicro5.3"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"python-tornado-debugsource", rpm:"python-tornado-debugsource~4.5.3~150000.3.6.1", rls:"openSUSELeapMicro5.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-tornado-debuginfo", rpm:"python-tornado-debuginfo~4.5.3~150000.3.6.1", rls:"openSUSELeapMicro5.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-tornado-debuginfo", rpm:"python3-tornado-debuginfo~4.5.3~150000.3.6.1", rls:"openSUSELeapMicro5.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-tornado", rpm:"python3-tornado~4.5.3~150000.3.6.1", rls:"openSUSELeapMicro5.4"))) {
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
