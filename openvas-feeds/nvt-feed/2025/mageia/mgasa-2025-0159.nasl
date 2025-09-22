# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2025.0159");
  script_cve_id("CVE-2025-4050", "CVE-2025-4051", "CVE-2025-4052", "CVE-2025-4096", "CVE-2025-4372", "CVE-2025-4609", "CVE-2025-4664");
  script_tag(name:"creation_date", value:"2025-05-26 04:12:01 +0000 (Mon, 26 May 2025)");
  script_version("2025-05-27T05:40:44+0000");
  script_tag(name:"last_modification", value:"2025-05-27 05:40:44 +0000 (Tue, 27 May 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-05-16 18:50:52 +0000 (Fri, 16 May 2025)");

  script_name("Mageia: Security Advisory (MGASA-2025-0159)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA9");

  script_xref(name:"Advisory-ID", value:"MGASA-2025-0159");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2025-0159.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=34235");
  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2025/04/stable-channel-update-for-desktop_29.html");
  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2025/05/stable-channel-update-for-desktop.html");
  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2025/05/stable-channel-update-for-desktop_14.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'chromium-browser-stable' package(s) announced via the MGASA-2025-0159 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Heap buffer overflow in HTML. (CVE-2025-4096)
Out of bounds memory access in DevTools. (CVE-2025-4050)
Insufficient data validation in DevTools. (CVE-2025-4051)
Inappropriate implementation in DevTools. (CVE-2025-4052)
Use after free in WebAudio. (CVE-2025-4372)
Insufficient policy enforcement in Loader. (CVE-2025-4664)
Incorrect handle provided in unspecified circumstances in Mojo.
(CVE-2025-4609)");

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

  if(!isnull(res = isrpmvuln(pkg:"chromium-browser", rpm:"chromium-browser~136.0.7103.113~1.mga9.tainted", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-browser-stable", rpm:"chromium-browser-stable~136.0.7103.113~1.mga9.tainted", rls:"MAGEIA9"))) {
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
