# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2025.0097");
  script_cve_id("CVE-2021-40647");
  script_tag(name:"creation_date", value:"2025-03-17 15:24:51 +0000 (Mon, 17 Mar 2025)");
  script_version("2025-03-18T05:38:50+0000");
  script_tag(name:"last_modification", value:"2025-03-18 05:38:50 +0000 (Tue, 18 Mar 2025)");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-09-14 19:52:17 +0000 (Wed, 14 Sep 2022)");

  script_name("Mageia: Security Advisory (MGASA-2025-0097)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA9");

  script_xref(name:"Advisory-ID", value:"MGASA-2025-0097");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2025-0097.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=34072");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/BAS4Z6KUDJQV22DP5BTQX56WVFT3FF32/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'man2html' package(s) announced via the MGASA-2025-0097 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"In man2html 1.6g, a specific string being read in from a file will
overwrite the size parameter in the top chunk of the heap. This at least
causes the program to segmentation abort if the heap size parameter
isn't aligned correctly. In versions before GLIBC version 2.29 and
if aligned correctly, it allows arbitrary writes anywhere in the program's
memory.");

  script_tag(name:"affected", value:"'man2html' package(s) on Mageia 9.");

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

  if(!isnull(res = isrpmvuln(pkg:"man2html", rpm:"man2html~1.6~6.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"man2html-core", rpm:"man2html-core~1.6~6.1.mga9", rls:"MAGEIA9"))) {
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
