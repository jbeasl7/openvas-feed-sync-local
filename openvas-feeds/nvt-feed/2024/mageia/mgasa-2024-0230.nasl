# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2024.0230");
  script_cve_id("CVE-2024-5830", "CVE-2024-5831", "CVE-2024-5832", "CVE-2024-5833", "CVE-2024-5834", "CVE-2024-5835", "CVE-2024-5836", "CVE-2024-5837", "CVE-2024-5838", "CVE-2024-5839", "CVE-2024-5840", "CVE-2024-5841", "CVE-2024-5842", "CVE-2024-5843", "CVE-2024-5844", "CVE-2024-5845", "CVE-2024-5846", "CVE-2024-5847");
  script_tag(name:"creation_date", value:"2024-06-21 04:10:54 +0000 (Fri, 21 Jun 2024)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-06-20 13:05:43 +0000 (Thu, 20 Jun 2024)");

  script_name("Mageia: Security Advisory (MGASA-2024-0230)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA9");

  script_xref(name:"Advisory-ID", value:"MGASA-2024-0230");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2024-0230.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=33308");
  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2024/06/stable-channel-update-for-desktop.html");
  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2024/06/stable-channel-update-for-desktop_13.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'chromium-browser-stable' package(s) announced via the MGASA-2024-0230 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The chromium-browser-stable package has been updated to the
126.0.6478.61 release. It includes 21 security fixes.
Some of them are:
* High CVE-2024-5830: Type Confusion in V8. Reported by Man Yue Mo of
GitHub Security Lab on 2024-05-24
* High CVE-2024-5831: Use after free in Dawn. Reported by wgslfuzz on
2024-05-07
* High CVE-2024-5832: Use after free in Dawn. Reported by wgslfuzz on
2024-05-13
* High CVE-2024-5833: Type Confusion in V8. Reported by @ginggilBesel on
2024-05-24
* High CVE-2024-5834: Inappropriate implementation in Dawn. Reported by
gelatin dessert on 2024-05-26
* High CVE-2024-5835: Heap buffer overflow in Tab Groups. Reported by
Weipeng Jiang (@Krace) of VRI on 2024-05-22
* High CVE-2024-5836: Inappropriate Implementation in DevTools. Reported
by Allen Ding on 2024-05-21
* High CVE-2024-5837: Type Confusion in V8. Reported by Anonymous on
2024-05-23
* High CVE-2024-5838: Type Confusion in V8. Reported by Zhenghang Xiao
(@Kipreyyy) on 2024-05-24
* Medium CVE-2024-5839: Inappropriate Implementation in Memory
Allocator. Reported by Micky on 2024-05-13
* Medium CVE-2024-5840: Policy Bypass in CORS. Reported by Matt Howard
on 2024-01-17
* Medium CVE-2024-5841: Use after free in V8. Reported by Cassidy
Kim(@cassidy6564) on 2024-02-26
* Medium CVE-2024-5842: Use after free in Browser UI. Reported by Sven
Dysthe (@svn_dy) on 2023-01-12
* Medium CVE-2024-5843: Inappropriate implementation in Downloads.
Reported by hjy79425575 on 2024-04-12
* Medium CVE-2024-5844: Heap buffer overflow in Tab Strip. Reported by
Sri on 2024-04-01
* Medium CVE-2024-5845: Use after free in Audio. Reported by anonymous
on 2024-05-13
* Medium CVE-2024-5846: Use after free in PDFium. Reported by Han Zheng
(HexHive) on 2024-05-16
* Medium CVE-2024-5847: Use after free in PDFium. Reported by Han Zheng
(HexHive) on 2024-05-18
Please, do note, only x86_64 is supported since some versions ago.
i586 support for linux was stopped some years ago and the community is
not able to provide patches anymore for the latest Chromium code.");

  script_tag(name:"affected", value:"'chromium-browser-stable' package(s) on Mageia 9.");

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

  if(!isnull(res = isrpmvuln(pkg:"chromium-browser", rpm:"chromium-browser~126.0.6478.61~1.mga9.tainted", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-browser-stable", rpm:"chromium-browser-stable~126.0.6478.61~1.mga9.tainted", rls:"MAGEIA9"))) {
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
