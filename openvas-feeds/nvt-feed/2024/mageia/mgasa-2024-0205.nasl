# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2024.0205");
  script_cve_id("CVE-2024-5493", "CVE-2024-5494", "CVE-2024-5495", "CVE-2024-5496", "CVE-2024-5497", "CVE-2024-5498", "CVE-2024-5499");
  script_tag(name:"creation_date", value:"2024-06-04 04:11:12 +0000 (Tue, 04 Jun 2024)");
  script_version("2025-01-09T06:16:22+0000");
  script_tag(name:"last_modification", value:"2025-01-09 06:16:22 +0000 (Thu, 09 Jan 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-12-26 16:07:06 +0000 (Thu, 26 Dec 2024)");

  script_name("Mageia: Security Advisory (MGASA-2024-0205)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA9");

  script_xref(name:"Advisory-ID", value:"MGASA-2024-0205");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2024-0205.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=33261");
  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2024/05/stable-channel-update-for-desktop_30.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'chromium-browser-stable' package(s) announced via the MGASA-2024-0205 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The chromium-browser-stable package has been updated to the
125.0.6422.141 release. It includes 11 security fixes.
Some of them are:
* High CVE-2024-5493: Heap buffer overflow in WebRTC. Reported by
Cassidy Kim(@cassidy6564) on 2024-05-11
* High CVE-2024-5494: Use after free in Dawn. Reported by wgslfuzz on
2024-05-01
* High CVE-2024-5495: Use after free in Dawn. Reported by wgslfuzz on
2024-05-01
* High CVE-2024-5496: Use after free in Media Session. Reported by
Cassidy Kim(@cassidy6564) on 2024-05-06
* High CVE-2024-5497: Out of bounds memory access in Keyboard Inputs.
Reported by zh1x1an1221 of Ant Group Tianqiong Security Lab on
2024-05-07
* High CVE-2024-5498: Use after free in Presentation API. Reported by
anymous on 2024-05-09
* High CVE-2024-5499: Out of bounds write in Streams API. Reported by
anonymous on 2024-05-11
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

  if(!isnull(res = isrpmvuln(pkg:"chromium-browser", rpm:"chromium-browser~125.0.6422.141~1.mga9.tainted", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-browser-stable", rpm:"chromium-browser-stable~125.0.6422.141~1.mga9.tainted", rls:"MAGEIA9"))) {
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
