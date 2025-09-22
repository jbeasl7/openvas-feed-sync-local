# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2013.0321");
  script_cve_id("CVE-2013-2925", "CVE-2013-2926", "CVE-2013-2927", "CVE-2013-2928");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-02-02T05:06:08+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:08 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Mageia: Security Advisory (MGASA-2013-0321)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA(2|3)");

  script_xref(name:"Advisory-ID", value:"MGASA-2013-0321");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2013-0321.html");
  script_xref(name:"URL", value:"http://googlechromereleases.blogspot.com/2013/10/stable-channel-update_15.html");
  script_xref(name:"URL", value:"http://googlechromereleases.blogspot.com/2013/10/stable-channel-update_22.html");
  script_xref(name:"URL", value:"http://www.debian.org/security/2013/dsa-2785");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=11554");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'chromium-browser-stable' package(s) announced via the MGASA-2013-0321 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated chromium-browser-stable packages fix security vulnerabilities:

Atte Kettunen of OUSPG discover a use-after-free issue in Blink's XML HTTP
request implementation (CVE-2013-2925).

cloudfuzzer discovered a use-after-free issue in the list indenting
implementation (CVE-2013-2926).

cloudfuzzer discovered a use-after-free issue in the HTML form submission
implementation (CVE-2013-2927).

The chrome 30 development team found various issues from internal fuzzing,
audits, and other studies (CVE-2013-2928).

This updates to the newest version from the Linux stable channel, fixing
these and several other issues.");

  script_tag(name:"affected", value:"'chromium-browser-stable' package(s) on Mageia 2, Mageia 3.");

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

if(release == "MAGEIA2") {

  if(!isnull(res = isrpmvuln(pkg:"chromium-browser", rpm:"chromium-browser~30.0.1599.114~1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-browser-stable", rpm:"chromium-browser-stable~30.0.1599.114~1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "MAGEIA3") {

  if(!isnull(res = isrpmvuln(pkg:"chromium-browser", rpm:"chromium-browser~30.0.1599.114~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-browser", rpm:"chromium-browser~30.0.1599.114~1.mga3.tainted", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-browser-stable", rpm:"chromium-browser-stable~30.0.1599.114~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-browser-stable", rpm:"chromium-browser-stable~30.0.1599.114~1.mga3.tainted", rls:"MAGEIA3"))) {
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
