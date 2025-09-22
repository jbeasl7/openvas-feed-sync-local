# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833704");
  script_version("2025-02-26T05:38:41+0000");
  script_cve_id("CVE-2021-45930", "CVE-2023-32573");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-05-23 17:24:32 +0000 (Tue, 23 May 2023)");
  script_tag(name:"creation_date", value:"2024-03-04 07:25:41 +0000 (Mon, 04 Mar 2024)");
  script_name("openSUSE: Security Advisory for libqt5 (SUSE-SU-2023:2981-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.4");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:2981-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/LZSP7YM5BFQ55I7Y7SF2UC6ONOGGSNE7");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libqt5'
  package(s) announced via the SUSE-SU-2023:2981-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for libqt5-qtsvg fixes the following issues:

  * CVE-2021-45930: Fixed an out-of-bounds write that may have lead to a denial-
      of-service (bsc#1196654).

  * CVE-2023-32573: Fixed missing initialization of QtSvg QSvgFont m_unitsPerEm
      variable (bsc#1211298).

  ##");

  script_tag(name:"affected", value:"'libqt5' package(s) on openSUSE Leap 15.4.");

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

  if(!isnull(res = isrpmvuln(pkg:"libQt5Svg5-32bit", rpm:"libQt5Svg5-32bit~5.15.2+kde16~150400.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5-qtsvg-devel-32bit", rpm:"libqt5-qtsvg-devel-32bit~5.15.2+kde16~150400.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt5Svg5-32bit-debuginfo", rpm:"libQt5Svg5-32bit-debuginfo~5.15.2+kde16~150400.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5-qtsvg-examples-debuginfo", rpm:"libqt5-qtsvg-examples-debuginfo~5.15.2+kde16~150400.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5-qtsvg-devel", rpm:"libqt5-qtsvg-devel~5.15.2+kde16~150400.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5-qtsvg-examples", rpm:"libqt5-qtsvg-examples~5.15.2+kde16~150400.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5-qtsvg-debugsource", rpm:"libqt5-qtsvg-debugsource~5.15.2+kde16~150400.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt5Svg5", rpm:"libQt5Svg5~5.15.2+kde16~150400.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt5Svg5-debuginfo", rpm:"libQt5Svg5-debuginfo~5.15.2+kde16~150400.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5-qtsvg-private-headers-devel", rpm:"libqt5-qtsvg-private-headers-devel~5.15.2+kde16~150400.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt5Svg5-64bit", rpm:"libQt5Svg5-64bit~5.15.2+kde16~150400.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt5Svg5-64bit-debuginfo", rpm:"libQt5Svg5-64bit-debuginfo~5.15.2+kde16~150400.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5-qtsvg-devel-64bit", rpm:"libqt5-qtsvg-devel-64bit~5.15.2+kde16~150400.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt5Svg5-32bit", rpm:"libQt5Svg5-32bit~5.15.2+kde16~150400.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5-qtsvg-devel-32bit", rpm:"libqt5-qtsvg-devel-32bit~5.15.2+kde16~150400.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt5Svg5-32bit-debuginfo", rpm:"libQt5Svg5-32bit-debuginfo~5.15.2+kde16~150400.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5-qtsvg-examples-debuginfo", rpm:"libqt5-qtsvg-examples-debuginfo~5.15.2+kde16~150400.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5-qtsvg-devel", rpm:"libqt5-qtsvg-devel~5.15.2+kde16~150400.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5-qtsvg-examples", rpm:"libqt5-qtsvg-examples~5.15.2+kde16~150400.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5-qtsvg-debugsource", rpm:"libqt5-qtsvg-debugsource~5.15.2+kde16~150400.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt5Svg5", rpm:"libQt5Svg5~5.15.2+kde16~150400.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt5Svg5-debuginfo", rpm:"libQt5Svg5-debuginfo~5.15.2+kde16~150400.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5-qtsvg-private-headers-devel", rpm:"libqt5-qtsvg-private-headers-devel~5.15.2+kde16~150400.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt5Svg5-64bit", rpm:"libQt5Svg5-64bit~5.15.2+kde16~150400.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt5Svg5-64bit-debuginfo", rpm:"libQt5Svg5-64bit-debuginfo~5.15.2+kde16~150400.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5-qtsvg-devel-64bit", rpm:"libqt5-qtsvg-devel-64bit~5.15.2+kde16~150400.3.3.1", rls:"openSUSELeap15.4"))) {
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