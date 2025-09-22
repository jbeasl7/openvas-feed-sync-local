# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2021.0555");
  script_cve_id("CVE-2021-4052", "CVE-2021-4053", "CVE-2021-4054", "CVE-2021-4055", "CVE-2021-4056", "CVE-2021-4057", "CVE-2021-4058", "CVE-2021-4059", "CVE-2021-4061", "CVE-2021-4062", "CVE-2021-4063", "CVE-2021-4064", "CVE-2021-4065", "CVE-2021-4066", "CVE-2021-4067", "CVE-2021-4068", "CVE-2021-4078", "CVE-2021-4079");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-02-02T05:06:09+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:09 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-12-28 20:50:47 +0000 (Tue, 28 Dec 2021)");

  script_name("Mageia: Security Advisory (MGASA-2021-0555)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2021-0555");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2021-0555.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=29744");
  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2021/12/stable-channel-update-for-desktop.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'chromium-browser-stable' package(s) announced via the MGASA-2021-0555 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"CVE-2021-4052: Use after free in web apps.
CVE-2021-4053: Use after free in UI.
CVE-2021-4079: Out of bounds write in WebRTC.
CVE-2021-4054: Incorrect security UI in autofill.
CVE-2021-4078: Type confusion in V8.
CVE-2021-4055: Heap buffer overflow in extensions.
CVE-2021-4056: Type Confusion in loader.
CVE-2021-4057: Use after free in file API.
CVE-2021-4058: Heap buffer overflow in ANGLE.
CVE-2021-4059: Insufficient data validation in loader.
CVE-2021-4061: Type Confusion in V8.
CVE-2021-4062: Heap buffer overflow in BFCache.
CVE-2021-4063: Use after free in developer tools.
CVE-2021-4064: Use after free in screen capture.
CVE-2021-4065: Use after free in autofill.
CVE-2021-4066: Integer underflow in ANGLE.
CVE-2021-4067: Use after free in window manager.
CVE-2021-4068: Insufficient validation of untrusted input in new tab page.");

  script_tag(name:"affected", value:"'chromium-browser-stable' package(s) on Mageia 8.");

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

if(release == "MAGEIA8") {

  if(!isnull(res = isrpmvuln(pkg:"chromium-browser", rpm:"chromium-browser~96.0.4664.93~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-browser-stable", rpm:"chromium-browser-stable~96.0.4664.93~1.mga8", rls:"MAGEIA8"))) {
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
