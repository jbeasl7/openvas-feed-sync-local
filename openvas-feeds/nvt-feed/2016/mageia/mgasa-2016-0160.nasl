# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.131292");
  script_cve_id("CVE-2016-1660", "CVE-2016-1661", "CVE-2016-1662", "CVE-2016-1663", "CVE-2016-1664", "CVE-2016-1665", "CVE-2016-1666");
  script_tag(name:"creation_date", value:"2016-05-09 11:17:54 +0000 (Mon, 09 May 2016)");
  script_version("2024-10-23T05:05:58+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:58 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-05-16 17:08:09 +0000 (Mon, 16 May 2016)");

  script_name("Mageia: Security Advisory (MGASA-2016-0160)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA5");

  script_xref(name:"Advisory-ID", value:"MGASA-2016-0160");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2016-0160.html");
  script_xref(name:"URL", value:"http://googlechromereleases.blogspot.com/2016/04/stable-channel-update_20.html");
  script_xref(name:"URL", value:"http://googlechromereleases.blogspot.com/2016/04/stable-channel-update_28.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=18291");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'chromium-browser-stable' package(s) announced via the MGASA-2016-0160 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Chromium-browser-stable 50.0.2661.94 fixes several security issues: an
out-of-bounds write problem in Blink (CVE-2016-1660), memory corruption in
cross-process frames (CVE-2016-1661), use-after-free bugs in extensions
(CVE-2016-1662) and in Blink's V8 bindings (CVE-2016-1663), an address bar
spoofing vulnerability (CVE-2016-1664), an information leak in V8
(CVE-2016-1665), and various fixes from upstream's internal audits, fuzzing, and
other initiatives (CVE-2015-1666).");

  script_tag(name:"affected", value:"'chromium-browser-stable' package(s) on Mageia 5.");

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

if(release == "MAGEIA5") {

  if(!isnull(res = isrpmvuln(pkg:"chromium-browser", rpm:"chromium-browser~50.0.2661.94~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-browser-stable", rpm:"chromium-browser-stable~50.0.2661.94~1.mga5", rls:"MAGEIA5"))) {
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
