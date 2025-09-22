# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833175");
  script_version("2025-02-26T05:38:41+0000");
  script_cve_id("CVE-2023-36661");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-07-06 18:02:31 +0000 (Thu, 06 Jul 2023)");
  script_tag(name:"creation_date", value:"2024-03-04 08:01:51 +0000 (Mon, 04 Mar 2024)");
  script_name("openSUSE: Security Advisory for xmltooling (SUSE-SU-2023:3089-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=(openSUSELeap15\.4|openSUSELeap15\.5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:3089-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/3B6NFW5OFRNL7OAAUS6V77AW3VNX4G24");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'xmltooling'
  package(s) announced via the SUSE-SU-2023:3089-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for xmltooling fixes the following issues:

  * CVE-2023-36661: Fix server-side request forgery vulnerability (bsc#1212359)

  ##");

  script_tag(name:"affected", value:"'xmltooling' package(s) on openSUSE Leap 15.4, openSUSE Leap 15.5.");

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

  if(!isnull(res = isrpmvuln(pkg:"libxmltooling-lite9", rpm:"libxmltooling-lite9~3.1.0~150300.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxmltooling9", rpm:"libxmltooling9~3.1.0~150300.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xmltooling-debugsource", rpm:"xmltooling-debugsource~3.1.0~150300.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xmltooling-schemas", rpm:"xmltooling-schemas~3.1.0~150300.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxmltooling-lite9-debuginfo", rpm:"libxmltooling-lite9-debuginfo~3.1.0~150300.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xmltooling-debuginfo", rpm:"xmltooling-debuginfo~3.1.0~150300.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxmltooling-devel", rpm:"libxmltooling-devel~3.1.0~150300.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxmltooling9-debuginfo", rpm:"libxmltooling9-debuginfo~3.1.0~150300.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxmltooling-lite9", rpm:"libxmltooling-lite9~3.1.0~150300.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxmltooling9", rpm:"libxmltooling9~3.1.0~150300.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xmltooling-debugsource", rpm:"xmltooling-debugsource~3.1.0~150300.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xmltooling-schemas", rpm:"xmltooling-schemas~3.1.0~150300.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxmltooling-lite9-debuginfo", rpm:"libxmltooling-lite9-debuginfo~3.1.0~150300.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xmltooling-debuginfo", rpm:"xmltooling-debuginfo~3.1.0~150300.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxmltooling-devel", rpm:"libxmltooling-devel~3.1.0~150300.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxmltooling9-debuginfo", rpm:"libxmltooling9-debuginfo~3.1.0~150300.3.3.1", rls:"openSUSELeap15.4"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"libxmltooling-lite9", rpm:"libxmltooling-lite9~3.1.0~150300.3.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxmltooling9", rpm:"libxmltooling9~3.1.0~150300.3.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xmltooling-debugsource", rpm:"xmltooling-debugsource~3.1.0~150300.3.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xmltooling-schemas", rpm:"xmltooling-schemas~3.1.0~150300.3.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxmltooling-lite9-debuginfo", rpm:"libxmltooling-lite9-debuginfo~3.1.0~150300.3.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xmltooling-debuginfo", rpm:"xmltooling-debuginfo~3.1.0~150300.3.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxmltooling-devel", rpm:"libxmltooling-devel~3.1.0~150300.3.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxmltooling9-debuginfo", rpm:"libxmltooling9-debuginfo~3.1.0~150300.3.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxmltooling-lite9", rpm:"libxmltooling-lite9~3.1.0~150300.3.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxmltooling9", rpm:"libxmltooling9~3.1.0~150300.3.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xmltooling-debugsource", rpm:"xmltooling-debugsource~3.1.0~150300.3.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xmltooling-schemas", rpm:"xmltooling-schemas~3.1.0~150300.3.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxmltooling-lite9-debuginfo", rpm:"libxmltooling-lite9-debuginfo~3.1.0~150300.3.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xmltooling-debuginfo", rpm:"xmltooling-debuginfo~3.1.0~150300.3.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxmltooling-devel", rpm:"libxmltooling-devel~3.1.0~150300.3.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxmltooling9-debuginfo", rpm:"libxmltooling9-debuginfo~3.1.0~150300.3.3.1", rls:"openSUSELeap15.5"))) {
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