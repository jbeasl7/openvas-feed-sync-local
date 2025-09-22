# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2020.0174");
  script_cve_id("CVE-2020-6423", "CVE-2020-6430", "CVE-2020-6431", "CVE-2020-6432", "CVE-2020-6433", "CVE-2020-6434", "CVE-2020-6435", "CVE-2020-6436", "CVE-2020-6437", "CVE-2020-6438", "CVE-2020-6439", "CVE-2020-6440", "CVE-2020-6441", "CVE-2020-6442", "CVE-2020-6443", "CVE-2020-6444", "CVE-2020-6445", "CVE-2020-6446", "CVE-2020-6447", "CVE-2020-6448", "CVE-2020-6450", "CVE-2020-6451", "CVE-2020-6452", "CVE-2020-6454", "CVE-2020-6455", "CVE-2020-6456");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-02-02T05:06:09+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:09 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-04-14 13:40:17 +0000 (Tue, 14 Apr 2020)");

  script_name("Mageia: Security Advisory (MGASA-2020-0174)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA7");

  script_xref(name:"Advisory-ID", value:"MGASA-2020-0174");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2020-0174.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=26470");
  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2020/03/stable-channel-update-for-desktop_31.html");
  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2020/04/stable-channel-update-for-desktop_7.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'chromium-browser-stable' package(s) announced via the MGASA-2020-0174 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Chromium-browser 81.0.4044.92 fixes security issues:

Multiple flaws were found in the way Chromium 80.0.3987.149 processes
various types of web content, where loading a web page containing
malicious content could cause Chromium to crash, execute arbitrary code,
or disclose sensitive information. (CVE-2020-6423, CVE-2020-6430,
CVE-2020-6431, CVE-2020-6432, CVE-2020-6433, CVE-2020-6434, CVE-2020-6435,
CVE-2020-6436, CVE-2020-6437, CVE-2020-6438, CVE-2020-6439, CVE-2020-6440,
CVE-2020-6441, CVE-2020-6442, CVE-2020-6443, CVE-2020-6444, CVE-2020-6445,
CVE-2020-6446, CVE-2020-6447, CVE-2020-6448, CVE-2020-6450, CVE-2020-6451,
CVE-2020-6452, CVE-2020-6454, CVE-2020-6455, CVE-2020-6456)");

  script_tag(name:"affected", value:"'chromium-browser-stable' package(s) on Mageia 7.");

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

if(release == "MAGEIA7") {

  if(!isnull(res = isrpmvuln(pkg:"chromium-browser", rpm:"chromium-browser~81.0.4044.92~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-browser-stable", rpm:"chromium-browser-stable~81.0.4044.92~1.mga7", rls:"MAGEIA7"))) {
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
