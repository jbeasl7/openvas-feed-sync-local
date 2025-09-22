# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2025.0091");
  script_cve_id("CVE-2025-0444", "CVE-2025-0445", "CVE-2025-0451", "CVE-2025-0995", "CVE-2025-0996", "CVE-2025-0997", "CVE-2025-0998", "CVE-2025-0999", "CVE-2025-1006", "CVE-2025-1426", "CVE-2025-1914", "CVE-2025-1915", "CVE-2025-1916", "CVE-2025-1917", "CVE-2025-1918", "CVE-2025-1919", "CVE-2025-1921", "CVE-2025-1922");
  script_tag(name:"creation_date", value:"2025-03-10 04:08:11 +0000 (Mon, 10 Mar 2025)");
  script_version("2025-03-10T05:35:40+0000");
  script_tag(name:"last_modification", value:"2025-03-10 05:35:40 +0000 (Mon, 10 Mar 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Mageia: Security Advisory (MGASA-2025-0091)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA9");

  script_xref(name:"Advisory-ID", value:"MGASA-2025-0091");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2025-0091.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=34012");
  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2025/02/stable-channel-update-for-desktop.html");
  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2025/02/stable-channel-update-for-desktop_12.html");
  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2025/02/stable-channel-update-for-desktop_18.html");
  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2025/02/stable-channel-update-for-desktop_25.html");
  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2025/03/stable-channel-update-for-desktop.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'chromium-browser-stable' package(s) announced via the MGASA-2025-0091 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"High CVE-2025-1914: Out of bounds read in V8.
Medium CVE-2025-1915: Improper Limitation of a Pathname to a Restricted
Directory in DevTools.
Medium CVE-2025-1916: Use after free in Profiles.
Medium CVE-2025-1917: Inappropriate Implementation in Browser UI.
Medium CVE-2025-1918: Out of bounds read in PDFium.
Medium CVE-2025-1919: Out of bounds read in Media.
Medium CVE-2025-1921: Inappropriate Implementation in Media
Low CVE-2025-1922: Inappropriate Implementation in Selection.
Low CVE-2025-1923: Inappropriate Implementation in Permission Prompts.
And more, please see the references.");

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

  if(!isnull(res = isrpmvuln(pkg:"chromium-browser", rpm:"chromium-browser~134.0.6998.35~1.mga9.tainted", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-browser-stable", rpm:"chromium-browser-stable~134.0.6998.35~1.mga9.tainted", rls:"MAGEIA9"))) {
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
