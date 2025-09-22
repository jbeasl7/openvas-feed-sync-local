# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2022.0376");
  script_cve_id("CVE-2022-3445", "CVE-2022-3446", "CVE-2022-3447", "CVE-2022-3448", "CVE-2022-3449", "CVE-2022-3450");
  script_tag(name:"creation_date", value:"2022-10-19 04:46:32 +0000 (Wed, 19 Oct 2022)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-11-10 18:51:56 +0000 (Thu, 10 Nov 2022)");

  script_name("Mageia: Security Advisory (MGASA-2022-0376)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2022-0376");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2022-0376.html");
  script_xref(name:"URL", value:"https://blog.chromium.org/2022/09/chrome-106-beta-new-css-features.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=30961");
  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2022/10/stable-channel-update-for-desktop_11.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'chromium-browser-stable' package(s) announced via the MGASA-2022-0376 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The chromium-browser-stable package has been updated to the new 106 branch
with the 106.0.5249.119 version, fixing many bugs and 6 vulnerabilities.
Some of the security fixes are:

High CVE-2022-3445: Use after free in Skia. Reported by Nan Wang
(@eternalsakura13) and Yong Liu of 360 Vulnerability Research Institute on
2022-09-16
High CVE-2022-3446: Heap buffer overflow in WebSQL. Reported by Kaijie Xu
(@kaijieguigui) on 2022-09-26
High CVE-2022-3447: Inappropriate implementation in Custom Tabs. Reported
by Narendra Bhati of Suma Soft Pvt. Ltd. Pune (India) on 2022-09-22
High CVE-2022-3448: Use after free in Permissions API. Reported by raven
at KunLun lab on 2022-09-13
High CVE-2022-3449: Use after free in Safe Browsing. Reported by asnine on
2022-09-17
High CVE-2022-3450: Use after free in Peer Connection. Reported by
Anonymous on 2022-09-30");

  script_tag(name:"affected", value:"'chromium-browser-stable' package(s) on Mageia 8.");

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

  if(!isnull(res = isrpmvuln(pkg:"chromium-browser", rpm:"chromium-browser~106.0.5249.119~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-browser-stable", rpm:"chromium-browser-stable~106.0.5249.119~1.mga8", rls:"MAGEIA8"))) {
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
