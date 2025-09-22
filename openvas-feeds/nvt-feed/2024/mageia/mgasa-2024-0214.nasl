# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2024.0214");
  script_cve_id("CVE-2024-36041");
  script_tag(name:"creation_date", value:"2024-06-10 04:12:25 +0000 (Mon, 10 Jun 2024)");
  script_version("2024-07-09T05:05:54+0000");
  script_tag(name:"last_modification", value:"2024-07-09 05:05:54 +0000 (Tue, 09 Jul 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-07-08 16:46:20 +0000 (Mon, 08 Jul 2024)");

  script_name("Mageia: Security Advisory (MGASA-2024-0214)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA9");

  script_xref(name:"Advisory-ID", value:"MGASA-2024-0214");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2024-0214.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=33272");
  script_xref(name:"URL", value:"https://kde.org/info/security/advisory-20240531-1.txt");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'plasma-workspace' package(s) announced via the MGASA-2024-0214 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"KSmserver, KDE's XSMP manager, incorrectly allows connections via ICE
based purely on the host, allowing all local connections. This allows
another user on the same machine to gain access to the session
manager.
A well crafted client could use the session restore feature to execute
arbitrary code as the user on the next boot.");

  script_tag(name:"affected", value:"'plasma-workspace' package(s) on Mageia 9.");

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

if(release == "MAGEIA9") {

  if(!isnull(res = isrpmvuln(pkg:"lib64colorcorrect5", rpm:"lib64colorcorrect5~5.27.10~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64kfontinst5", rpm:"lib64kfontinst5~5.27.10~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64kfontinstui5", rpm:"lib64kfontinstui5~5.27.10~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64kworkspace5", rpm:"lib64kworkspace5~5.27.10~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64notificationmanager1", rpm:"lib64notificationmanager1~5.27.10~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64plasma-geolocation-interface5", rpm:"lib64plasma-geolocation-interface5~5.27.10~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64plasma-workspace-devel", rpm:"lib64plasma-workspace-devel~5.27.10~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64taskmanager6", rpm:"lib64taskmanager6~5.27.10~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64weather_ion7", rpm:"lib64weather_ion7~5.27.10~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcolorcorrect5", rpm:"libcolorcorrect5~5.27.10~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkfontinst5", rpm:"libkfontinst5~5.27.10~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkfontinstui5", rpm:"libkfontinstui5~5.27.10~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkworkspace5", rpm:"libkworkspace5~5.27.10~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnotificationmanager1", rpm:"libnotificationmanager1~5.27.10~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libplasma-geolocation-interface5", rpm:"libplasma-geolocation-interface5~5.27.10~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libplasma-workspace-devel", rpm:"libplasma-workspace-devel~5.27.10~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtaskmanager6", rpm:"libtaskmanager6~5.27.10~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libweather_ion7", rpm:"libweather_ion7~5.27.10~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"plasma-workspace", rpm:"plasma-workspace~5.27.10~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"plasma-workspace-handbook", rpm:"plasma-workspace-handbook~5.27.10~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"plasma-workspace-wayland", rpm:"plasma-workspace-wayland~5.27.10~1.1.mga9", rls:"MAGEIA9"))) {
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
