# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.131149");
  script_cve_id("CVE-2015-6764", "CVE-2015-6765", "CVE-2015-6766", "CVE-2015-6767", "CVE-2015-6768", "CVE-2015-6769", "CVE-2015-6770", "CVE-2015-6771", "CVE-2015-6772", "CVE-2015-6773", "CVE-2015-6774", "CVE-2015-6775", "CVE-2015-6776", "CVE-2015-6777", "CVE-2015-6778", "CVE-2015-6779", "CVE-2015-6780", "CVE-2015-6782", "CVE-2015-6784", "CVE-2015-6785", "CVE-2015-6786", "CVE-2015-6787");
  script_tag(name:"creation_date", value:"2015-12-10 09:05:52 +0000 (Thu, 10 Dec 2015)");
  script_version("2024-10-23T05:05:58+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:58 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2015-12-07 19:32:42 +0000 (Mon, 07 Dec 2015)");

  script_name("Mageia: Security Advisory (MGASA-2015-0467)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA5");

  script_xref(name:"Advisory-ID", value:"MGASA-2015-0467");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2015-0467.html");
  script_xref(name:"URL", value:"http://googlechromereleases.blogspot.com/2015/12/stable-channel-update.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=17272");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'chromium-browser-stable' package(s) announced via the MGASA-2015-0467 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Chromium-browser 47.0.2526.73 fixes several security issues:

Use-after-free bugs in AppCache (CVE-2015-6765, CVE-2015-6766, CVE-2015-6767).

Cross-origin bypass problems in DOM (CVE-2015-6768, CVE-2015-6770,
CVE-2015-6772).

A cross-origin bypass problem in core (CVE-2015-6769).

Out of bounds access bugs in v8 (CVE-2015-6771, CVE-2015-6764).

An out of bounds access in Skia (CVE-2015-6773).

A use-after-free bug in the Extensions component (CVE-2015-6774).

Type confusion in PDFium (CVE-2015-6775).

Out of bounds accesses in PDFium (CVE-2015-6776, CVE-2015-6778).

A use-after-free bug in DOM (CVE-2015-6777).

A scheme bypass in PDFium (CVE-2015-6779).

A use-after-free bug in Infobars (CVE-2015-6780).

An integer overflow in Sfntly (CVE-2015-6781).

Content spoofing in Omnibox (CVE-2015-6782).

An escaping issue in saved pages (CVE-2015-6784).

A wildcard matching issue in CSP (CVE-2015-6785).

A scheme bypass in CSP (CVE-2015-6786).

Various fixes from internal audits, fuzzing and other initiatives
(CVE-2015-6787).

Multiple vulnerabilities in V8 fixed in the 4.7 branch, up to version 4.7.80.23.");

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

  if(!isnull(res = isrpmvuln(pkg:"chromium-browser", rpm:"chromium-browser~47.0.2526.73~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-browser-stable", rpm:"chromium-browser-stable~47.0.2526.73~1.mga5", rls:"MAGEIA5"))) {
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
