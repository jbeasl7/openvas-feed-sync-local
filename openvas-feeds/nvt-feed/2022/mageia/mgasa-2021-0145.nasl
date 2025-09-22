# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2021.0145");
  script_cve_id("CVE-2021-21381");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-03-19 15:19:57 +0000 (Fri, 19 Mar 2021)");

  script_name("Mageia: Security Advisory (MGASA-2021-0145)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2021-0145");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2021-0145.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=28575");
  script_xref(name:"URL", value:"https://github.com/flatpak/flatpak/issues/4146");
  script_xref(name:"URL", value:"https://github.com/flatpak/flatpak/releases/tag/1.10.2");
  script_xref(name:"URL", value:"https://github.com/flatpak/flatpak/security/advisories/GHSA-xgh4-387p-hqpp");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'flatpak' package(s) announced via the MGASA-2021-0145 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A potential attack where a flatpak application could use custom formatted
.desktop files to gain access to files on the host system (CVE-2021-21381).");

  script_tag(name:"affected", value:"'flatpak' package(s) on Mageia 8.");

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

if(release == "MAGEIA8") {

  if(!isnull(res = isrpmvuln(pkg:"flatpak", rpm:"flatpak~1.10.2~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"flatpak-tests", rpm:"flatpak-tests~1.10.2~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64flatpak-devel", rpm:"lib64flatpak-devel~1.10.2~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64flatpak-gir1.0", rpm:"lib64flatpak-gir1.0~1.10.2~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64flatpak0", rpm:"lib64flatpak0~1.10.2~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libflatpak-devel", rpm:"libflatpak-devel~1.10.2~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libflatpak-gir1.0", rpm:"libflatpak-gir1.0~1.10.2~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libflatpak0", rpm:"libflatpak0~1.10.2~1.mga8", rls:"MAGEIA8"))) {
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
