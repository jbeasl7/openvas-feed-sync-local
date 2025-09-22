# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2024.0321");
  script_cve_id("CVE-2024-6988", "CVE-2024-6989", "CVE-2024-6991", "CVE-2024-6994", "CVE-2024-6995", "CVE-2024-6996", "CVE-2024-6997", "CVE-2024-6998", "CVE-2024-6999", "CVE-2024-7000", "CVE-2024-7001", "CVE-2024-7003", "CVE-2024-7004", "CVE-2024-7005");
  script_tag(name:"creation_date", value:"2024-10-07 09:59:37 +0000 (Mon, 07 Oct 2024)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-08-07 13:35:02 +0000 (Wed, 07 Aug 2024)");

  script_name("Mageia: Security Advisory (MGASA-2024-0321)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA9");

  script_xref(name:"Advisory-ID", value:"MGASA-2024-0321");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2024-0321.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=33443");
  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2024/07/stable-channel-update-for-desktop_23.html");
  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2024/07/stable-channel-update-for-desktop_30.html");
  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2024/08/stable-channel-update-for-desktop.html");
  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2024/08/stable-channel-update-for-desktop_13.html");
  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2024/08/stable-channel-update-for-desktop_21.html");
  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2024/08/stable-channel-update-for-desktop_28.html");
  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2024/09/stable-channel-update-for-desktop.html");
  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2024/09/stable-channel-update-for-desktop_10.html");
  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2024/09/stable-channel-update-for-desktop_17.html");
  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2024/09/stable-channel-update-for-desktop_24.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'chromium-browser-stable' package(s) announced via the MGASA-2024-0321 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Use after free in Downloads. (CVE-2024-6988)
Use after free in Loader. (CVE-2024-6989)
Use after free in Dawn. (CVE-2024-6991)
Heap buffer overflow in Layout. (CVE-2024-6994)
Inappropriate implementation in Fullscreen. (CVE-2024-6995)
Race in Frames. (CVE-2024-6996)
Use after free in Tabs. (CVE-2024-6997)
Use after free in User Education. (CVE-2024-6998)
Inappropriate implementation in FedCM. (CVE-2024-6999)
Use after free in CSS. (CVE-2024-7000)
Inappropriate implementation in HTML. (CVE-2024-7001)
Inappropriate implementation in FedCM. (CVE-2024-7003)
Insufficient validation of untrusted input in Safe Browsing.
(CVE-2024-7004)
Insufficient validation of untrusted input in Safe Browsing.
(CVE-2024-7005)
Uninitialized Use in Dawn. (CVE-2024-6990)
Out of bounds read in WebTransport. (CVE-2024-7255)
Insufficient data validation in Dawn. (CVE-2024-7256)
Out of bounds memory access in ANGLE. (CVE-2024-7532)
Use after free in Sharing. (CVE-2024-7533)
Type Confusion in V8. (CVE-2024-7550)
Heap buffer overflow in Layout. (CVE-2024-7534)
Inappropriate implementation in V8. (CVE-2024-7535)
Use after free in WebAudio. (CVE-2024-7536)
Use after free in Passwords. (CVE-2024-7964)
Inappropriate implementation in V8. (CVE-2024-7965)
Out of bounds memory access in Skia. (CVE-2024-7966)
Heap buffer overflow in Fonts. (CVE-2024-7967)
Use after free in Autofill. (CVE-2024-7968)
Type confusion in V8. (CVE-2024-7971)
Inappropriate implementation in V8. (CVE-2024-7972)
Heap buffer overflow in PDFium. (CVE-2024-7973)
Insufficient data validation in V8 API. (CVE-2024-7974)
Inappropriate implementation in Permissions. (CVE-2024-7975)
Inappropriate implementation in FedCM. (CVE-2024-7976)
Insufficient data validation in Installer. (CVE-2024-7977)
Insufficient policy enforcement in Data Transfer. (CVE-2024-7978)
Insufficient data validation in Installer. (CVE-2024-7979)
Insufficient data validation in Installer. (CVE-2024-7980)
Inappropriate implementation in Views. (CVE-2024-7981)
Inappropriate implementation in WebApp Installs. (CVE-2024-8033)
Inappropriate implementation in Custom Tabs. (CVE-2024-8034)
Inappropriate implementation in Extensions. (CVE-2024-8035)
Type Confusion in V8. (CVE-2024-7969)
Heap buffer overflow in Skia. (CVE-2024-8193)
Type Confusion in V8. (CVE-2024-8194)
Heap buffer overflow in Skia. (CVE-2024-8198)
Use after free in WebAudio. (CVE-2024-8362)
Out of bounds write in V8. (CVE-2024-7970)
Heap buffer overflow in Skia. (CVE-2024-8636)
Use after free in Media Router. (CVE-2024-8637)
Type Confusion in V8. (CVE-2024-8638)
Use after free in Autofill. (CVE-2024-8639)
Type Confusion in V8. (CVE-2024-8904)
Inappropriate implementation in V8. (CVE-2024-8905)
Incorrect security UI in Downloads. (CVE-2024-8906)
Insufficient data validation in Omnibox. (CVE-2024-8907)
Inappropriate implementation in Autofill. (CVE-2024-8908)
Inappropriate implementation in UI. ... [Please see the references for more information on the vulnerabilities]");

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

  if(!isnull(res = isrpmvuln(pkg:"chromium-browser", rpm:"chromium-browser~128.0.6613.137~1.mga9.tainted", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-browser-stable", rpm:"chromium-browser-stable~128.0.6613.137~1.mga9.tainted", rls:"MAGEIA9"))) {
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
