# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833507");
  script_version("2025-02-26T05:38:41+0000");
  script_cve_id("CVE-2020-23804", "CVE-2020-36024", "CVE-2022-37050", "CVE-2022-37051", "CVE-2022-38349");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-08-25 19:08:14 +0000 (Fri, 25 Aug 2023)");
  script_tag(name:"creation_date", value:"2024-03-04 07:36:23 +0000 (Mon, 04 Mar 2024)");
  script_name("openSUSE: Security Advisory for poppler (SUSE-SU-2023:3998-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.4");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:3998-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/3XATRPC35UIXYIRJXYVYQD64GIAMNLV6");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'poppler'
  package(s) announced via the SUSE-SU-2023:3998-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for poppler fixes the following issues:

  * CVE-2020-23804: Fixed uncontrolled recursion in pdfinfo and pdftops
      (bsc#1215422).

  * CVE-2020-36024: Fixed NULL Pointer Deference in `FoFiType1C:convertToType1`
      (bsc#1214257).

  * CVE-2022-37050: Fixed denial-of-service via savePageAs in PDFDoc.c
      (bsc#1214622).

  * CVE-2022-37051: Fixed abort in main() in pdfunite.cc (bsc#1214621).

  * CVE-2022-38349: Fixed reachable assertion in Object.h that will lead to
      denial of service (bsc#1214618).

  ##");

  script_tag(name:"affected", value:"'poppler' package(s) on openSUSE Leap 15.4.");

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

  if(!isnull(res = isrpmvuln(pkg:"libpoppler89-debuginfo", rpm:"libpoppler89-debuginfo~0.79.0~150200.3.21.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpoppler89", rpm:"libpoppler89~0.79.0~150200.3.21.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpoppler89-32bit-debuginfo", rpm:"libpoppler89-32bit-debuginfo~0.79.0~150200.3.21.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpoppler89-32bit", rpm:"libpoppler89-32bit~0.79.0~150200.3.21.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpoppler89-debuginfo", rpm:"libpoppler89-debuginfo~0.79.0~150200.3.21.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpoppler89", rpm:"libpoppler89~0.79.0~150200.3.21.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpoppler89-32bit-debuginfo", rpm:"libpoppler89-32bit-debuginfo~0.79.0~150200.3.21.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpoppler89-32bit", rpm:"libpoppler89-32bit~0.79.0~150200.3.21.2", rls:"openSUSELeap15.4"))) {
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