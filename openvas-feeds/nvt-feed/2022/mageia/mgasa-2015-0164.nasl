# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2015.0164");
  script_cve_id("CVE-2015-1235", "CVE-2015-1236", "CVE-2015-1237", "CVE-2015-1238", "CVE-2015-1240", "CVE-2015-1241", "CVE-2015-1242", "CVE-2015-1244", "CVE-2015-1245", "CVE-2015-1246", "CVE-2015-1247", "CVE-2015-1248", "CVE-2015-1249", "CVE-2015-3333");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Mageia: Security Advisory (MGASA-2015-0164)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA4");

  script_xref(name:"Advisory-ID", value:"MGASA-2015-0164");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2015-0164.html");
  script_xref(name:"URL", value:"http://googlechromereleases.blogspot.com/2015/04/stable-channel-update_14.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=15702");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'chromium-browser-stable' package(s) announced via the MGASA-2015-0164 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Chromium-browser 42.0.2311.90 fixes several security issues, among others a
cross-origin-bypass in HTML parser (CVE-2015-1235), a cross-origin-bypass
in Blink (CVE-2015-1236), a use-after-free in IPC (CVE-2015-1237), an
out-of-bounds write in Skia (CVE-2015-1238), an out-of-bounds read in WebGL
(CVE-2015-1240), Tap-Jacking (CVE-2015-1241), type confusion in V8
(CVE-2015-1242), HSTS bypass in WebSockets (CVE-2015-1244), a
use-after-free in PDFium (CVE-2015-1245), an out-of-bounds read in Blink
(CVE-2015-1246), scheme issues in OpenSearch, (CVE-2015-1247), and a
SafeBrowsing bypass (CVE-2015-1248). Also included are various fixes from
internal audits, fuzzing and other initiatives (CVE-2015-1249), and
multiple vulnerabilities in V8 have been fixed at the tip of the 4.2 branch
(currently 4.2.77.14) (CVE-2015-3333).");

  script_tag(name:"affected", value:"'chromium-browser-stable' package(s) on Mageia 4.");

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

if(release == "MAGEIA4") {

  if(!isnull(res = isrpmvuln(pkg:"chromium-browser", rpm:"chromium-browser~42.0.2311.90~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-browser-stable", rpm:"chromium-browser-stable~42.0.2311.90~1.mga4", rls:"MAGEIA4"))) {
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
