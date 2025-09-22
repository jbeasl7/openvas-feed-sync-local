# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2013.0249");
  script_cve_id("CVE-2013-2881", "CVE-2013-2882", "CVE-2013-2883", "CVE-2013-2884", "CVE-2013-2885", "CVE-2013-2886");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Mageia: Security Advisory (MGASA-2013-0249)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA(2|3)");

  script_xref(name:"Advisory-ID", value:"MGASA-2013-0249");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2013-0249.html");
  script_xref(name:"URL", value:"http://googlechromereleases.blogspot.com/2013/07/stable-channel-update_30.html");
  script_xref(name:"URL", value:"http://www.debian.org/security/2013/dsa-2732");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=10828");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=10922");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=9851");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'chromium-browser-stable' package(s) announced via the MGASA-2013-0249 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated chromium-browser-stable packages fix security vulnerabilities:

Karthik Bhargavan discovered a way to bypass the Same Origin Policy in frame
handling (CVE-2013-2881).

Cloudfuzzer discovered a type confusion issue in the V8 javascript library
(CVE-2013-2882).

Cloudfuzzer discovered a use-after-free issue in MutationObserver
(CVE-2013-2883).

Ivan Fratric of the Google Security Team discovered a use-after-free issue in
the DOM implementation (CVE-2013-2884).

Ivan Fratric of the Google Security Team discovered a use-after-free issue in
input handling (CVE-2013-2885).

The chrome 28 development team found various issues from internal fuzzing,
audits, and other studies (CVE-2013-2886).

This update provides version 28.0.1500.95, which fixes these issues.

Additionally, Google Sync should now work (mga#9851), and playing of media
files with certain codecs, such as mp3, should now work with the tainted
build (mga#10828) in Mageia 3.");

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

  if(!isnull(res = isrpmvuln(pkg:"chromium-browser", rpm:"chromium-browser~28.0.1500.95~1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-browser-stable", rpm:"chromium-browser-stable~28.0.1500.95~1.mga2", rls:"MAGEIA2"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"chromium-browser", rpm:"chromium-browser~28.0.1500.95~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-browser", rpm:"chromium-browser~28.0.1500.95~1.mga3.tainted", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-browser-stable", rpm:"chromium-browser-stable~28.0.1500.95~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-browser-stable", rpm:"chromium-browser-stable~28.0.1500.95~1.mga3.tainted", rls:"MAGEIA3"))) {
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
