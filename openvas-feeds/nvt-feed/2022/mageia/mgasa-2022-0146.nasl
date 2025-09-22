# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2022.0146");
  script_cve_id("CVE-2022-1232", "CVE-2022-1305", "CVE-2022-1306", "CVE-2022-1307", "CVE-2022-1308", "CVE-2022-1309", "CVE-2022-1310", "CVE-2022-1311", "CVE-2022-1312", "CVE-2022-1313", "CVE-2022-1314", "CVE-2022-1364");
  script_tag(name:"creation_date", value:"2022-04-20 04:37:20 +0000 (Wed, 20 Apr 2022)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-07-27 17:20:21 +0000 (Wed, 27 Jul 2022)");

  script_name("Mageia: Security Advisory (MGASA-2022-0146)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2022-0146");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2022-0146.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=30259");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=30276");
  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2022/04/stable-channel-update-for-desktop.html");
  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2022/04/stable-channel-update-for-desktop_11.html");
  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2022/04/stable-channel-update-for-desktop_14.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'chromium-browser-stable' package(s) announced via the MGASA-2022-0146 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The chromium-browser-stable package has been updated to the 100.0.4896.127
version, fixing many CVE, along with fixes from the 100.0.4896.75 and
100.0.4896.88 versions.

Google is aware that an exploit for CVE-2022-1364 exists in the wild.

[1315901] High CVE-2022-1364: Type Confusion in V8. Reported by Clement
Lecigne of Google's Threat Analysis Group on 2022-04-13
[1311641] High CVE-2022-1232: Type Confusion in V8. Reported by Sergei
Glazunov of Google Project Zero on 2022-03-30
[1285234] High CVE-2022-1305: Use after free in storage. Reported by
Anonymous on 2022-01-07
[1299287] High CVE-2022-1306: Inappropriate implementation in compositing.
Reported by Sven Dysthe on 2022-02-21
[1301873] High CVE-2022-1307: Inappropriate implementation in full screen.
Reported by Irvan Kurniawan (sourc7) on 2022-03-01
[1283050] High CVE-2022-1308: Use after free in BFCache. Reported by Samet
Bekmezci @sametbekmezci on 2021-12-28
[1106456] High CVE-2022-1309: Insufficient policy enforcement in developer
tools. Reported by David Erceg on 2020-07-17
[1307610] High CVE-2022-1310: Use after free in regular expressions.
Reported by Brendon Tiszka on 2022-03-18
[1310717] High CVE-2022-1311: Use after free in Chrome OS shell. Reported
by Nan Wang(@eternalsakura13) and Guang Gong of 360 Alpha Lab on
2022-03-28
[1311701] High CVE-2022-1312: Use after free in storage. Reported by
Leecraso and Guang Gong of 360 Vulnerability Research Institute on
2022-03-30
[1270539] Medium CVE-2022-1313: Use after free in tab groups. Reported by
Thomas Orlita on 2021-11-16
[1304658] Medium CVE-2022-1314: Type Confusion in V8. Reported by Bohan
Liu (@P4nda20371774) of Tencent Security Xuanwu Lab on 2022-03-09
[1315276] Various fixes from internal audits, fuzzing and other initiatives
[1316420] Various fixes from internal audits, fuzzing and other initiatives");

  script_tag(name:"affected", value:"'chromium-browser-stable' package(s) on Mageia 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");

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

  if(!isnull(res = isrpmvuln(pkg:"chromium-browser", rpm:"chromium-browser~100.0.4896.127~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-browser-stable", rpm:"chromium-browser-stable~100.0.4896.127~1.mga8", rls:"MAGEIA8"))) {
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
