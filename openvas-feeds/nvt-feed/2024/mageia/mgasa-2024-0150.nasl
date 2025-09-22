# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2024.0150");
  script_cve_id("CVE-2024-3157", "CVE-2024-3515", "CVE-2024-3516", "CVE-2024-3832", "CVE-2024-3833", "CVE-2024-3834", "CVE-2024-3837", "CVE-2024-3838", "CVE-2024-3839", "CVE-2024-3840", "CVE-2024-3841", "CVE-2024-3843", "CVE-2024-3844", "CVE-2024-3845", "CVE-2024-3846", "CVE-2024-3847", "CVE-2024-3914");
  script_tag(name:"creation_date", value:"2024-04-29 04:12:50 +0000 (Mon, 29 Apr 2024)");
  script_version("2025-01-09T06:16:22+0000");
  script_tag(name:"last_modification", value:"2025-01-09 06:16:22 +0000 (Thu, 09 Jan 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-12-19 16:22:30 +0000 (Thu, 19 Dec 2024)");

  script_name("Mageia: Security Advisory (MGASA-2024-0150)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA9");

  script_xref(name:"Advisory-ID", value:"MGASA-2024-0150");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2024-0150.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=33137");
  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2024/04/stable-channel-update-for-desktop_10.html");
  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2024/04/stable-channel-update-for-desktop_16.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'chromium-browser-stable' package(s) announced via the MGASA-2024-0150 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The chromium-browser-stable package has been updated to the
124.0.6367.60 release. It includes 23 security fixes.
Please, do note, only x86_64 is supported from now on.
i586 support for linux was stopped some years ago and the community is
not able to provide patches anymore for the latest Chromium code.
Some of the security fixes are:
* High CVE-2024-3832: Object corruption in V8. Reported by Man Yue Mo of
GitHub Security Lab on 2024-03-27
* High CVE-2024-3833: Object corruption in WebAssembly. Reported by Man
Yue Mo of GitHub Security Lab on 2024-03-27
* High CVE-2024-3914: Use after free in V8. Reported by Seunghyun Lee
(@0x10n) of KAIST Hacking Lab, via Pwn2Own 2024 on 2024-03-21
* High CVE-2024-3834: Use after free in Downloads. Reported by
ChaobinZhang on 2024-02-24
* Medium CVE-2024-3837: Use after free in QUIC. Reported by {rotiple,
dch3ck} of CW Research Inc. on 2024-01-15
* Medium CVE-2024-3838: Inappropriate implementation in Autofill.
Reported by KiriminAja on 2024-03-06
* Medium CVE-2024-3839: Out of bounds read in Fonts. Reported by Ronald
Crane (Zippenhop LLC) on 2024-01-16
* Medium CVE-2024-3840: Insufficient policy enforcement in Site
Isolation. Reported by Ahmed ElMasry on 2024-01-22
* Medium CVE-2024-3841: Insufficient data validation in Browser
Switcher. Reported by Oleg on 2024-03-19
* Medium CVE-2024-3843: Insufficient data validation in Downloads.
Reported by Azur on 2023-12-24
* Low CVE-2024-3844: Inappropriate implementation in Extensions.
Reported by Alesandro Ortiz on 2022-02-23
* Low CVE-2024-3845: Inappropriate implementation in Network. Reported
by Daniel Baulig on 2024-02-03
* Low CVE-2024-3846: Inappropriate implementation in Prompts. Reported
by Ahmed ElMasry on 2023-05-23
* Low CVE-2024-3847: Insufficient policy enforcement in WebUI. Reported
by Yan Zhu on 2024-03-08
* High CVE-2024-3157: Out of bounds write in Compositing. Reported by
DarkNavy on 2024-03-26
* High CVE-2024-3516: Heap buffer overflow in ANGLE. Reported by Bao
(zx) Pham and Toan (suto) Pham of Qrious Secure on 2024-03-09
* High CVE-2024-3515: Use after free in Dawn. Reported by wgslfuzz on
2024-03-25");

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

  if(!isnull(res = isrpmvuln(pkg:"chromium-browser", rpm:"chromium-browser~124.0.6367.60~1.mga9.tainted", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-browser-stable", rpm:"chromium-browser-stable~124.0.6367.60~1.mga9.tainted", rls:"MAGEIA9"))) {
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
