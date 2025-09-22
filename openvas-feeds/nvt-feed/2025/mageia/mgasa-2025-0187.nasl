# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2025.0187");
  script_cve_id("CVE-2025-5063", "CVE-2025-5064", "CVE-2025-5065", "CVE-2025-5066", "CVE-2025-5067", "CVE-2025-5068", "CVE-2025-5280", "CVE-2025-5281", "CVE-2025-5283", "CVE-2025-5419", "CVE-2025-5958", "CVE-2025-5959");
  script_tag(name:"creation_date", value:"2025-06-23 04:16:59 +0000 (Mon, 23 Jun 2025)");
  script_version("2025-06-23T05:41:09+0000");
  script_tag(name:"last_modification", value:"2025-06-23 05:41:09 +0000 (Mon, 23 Jun 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Mageia: Security Advisory (MGASA-2025-0187)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA9");

  script_xref(name:"Advisory-ID", value:"MGASA-2025-0187");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2025-0187.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=34340");
  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2025/05/stable-channel-update-for-desktop_27.html");
  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2025/06/stable-channel-update-for-desktop.html");
  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2025/06/stable-channel-update-for-desktop_10.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'chromium-browser-stable' package(s) announced via the MGASA-2025-0187 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"CVE-2025-5063: Use after free in Compositing.
CVE-2025-5280: Out of bounds write in V8.
CVE-2025-5064: Inappropriate implementation in Background Fetch API.
CVE-2025-5065: Inappropriate implementation in FileSystemAccess API.
CVE-2025-5066: Inappropriate implementation in Messages.
CVE-2025-5281: Inappropriate implementation in BFCache.
CVE-2025-5283: Use after free in libvpx.
CVE-2025-5067: Inappropriate implementation in Tab Strip.
CVE-2025-5419: Out of bounds read and write in V8.
CVE-2025-5068: Use after free in Blink.
CVE-2025-5958: Use after free in Media.
CVE-2025-5959: Type Confusion in V8.");

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

  if(!isnull(res = isrpmvuln(pkg:"chromium-browser", rpm:"chromium-browser~136.0.7103.113~2.mga9.tainted", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-browser-stable", rpm:"chromium-browser-stable~136.0.7103.113~2.mga9.tainted", rls:"MAGEIA9"))) {
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
