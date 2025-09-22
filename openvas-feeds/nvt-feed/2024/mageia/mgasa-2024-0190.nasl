# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2024.0190");
  script_cve_id("CVE-2024-4947", "CVE-2024-4948", "CVE-2024-4949", "CVE-2024-4950");
  script_tag(name:"creation_date", value:"2024-05-22 04:11:38 +0000 (Wed, 22 May 2024)");
  script_version("2025-01-09T06:16:22+0000");
  script_tag(name:"last_modification", value:"2025-01-09 06:16:22 +0000 (Thu, 09 Jan 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-11-27 19:25:14 +0000 (Wed, 27 Nov 2024)");

  script_name("Mageia: Security Advisory (MGASA-2024-0190)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA9");

  script_xref(name:"Advisory-ID", value:"MGASA-2024-0190");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2024-0190.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=33227");
  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2024/05/stable-channel-update-for-desktop_15.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'chromium-browser-stable' package(s) announced via the MGASA-2024-0190 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The chromium-browser-stable package has been updated to the
125.0.6422.60 release. It includes 9 security fixes.
Please, do note, only x86_64 is supported from now on.
i586 support for linux was stopped some years ago and the community is
not able to provide patches anymore for the latest Chromium code.
Some of the security fixes are:
* CVE-2024-4947: Type Confusion in V8. Reported by Vasily Berdnikov
(@vaber_b) and Boris Larin (@oct0xor) of Kaspersky on 2024-05-13
* High CVE-2024-4948: Use after free in Dawn. Reported by wgslfuzz on
2024-04-09
* Medium CVE-2024-4949: Use after free in V8. Reported by Ganjiang
Zhou(@refrain_areu) of ChaMd5-H1 team on 2024-02-24
* Low CVE-2024-4950: Inappropriate implementation in Downloads. Reported
by Shaheen Fazim on 2023-06-06
Google is aware that an exploit for CVE-2024-4947 exists in the wild.");

  script_tag(name:"affected", value:"'chromium-browser-stable' package(s) on Mageia 9.");

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

if(release == "MAGEIA9") {

  if(!isnull(res = isrpmvuln(pkg:"chromium-browser", rpm:"chromium-browser~125.0.6422.60~1.1.mga9.tainted", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-browser-stable", rpm:"chromium-browser-stable~125.0.6422.60~1.1.mga9.tainted", rls:"MAGEIA9"))) {
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
