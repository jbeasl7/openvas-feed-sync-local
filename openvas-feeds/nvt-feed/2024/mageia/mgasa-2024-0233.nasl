# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2024.0233");
  script_cve_id("CVE-2024-6100", "CVE-2024-6101", "CVE-2024-6102", "CVE-2024-6103");
  script_tag(name:"creation_date", value:"2024-06-25 04:11:23 +0000 (Tue, 25 Jun 2024)");
  script_version("2024-06-25T05:05:27+0000");
  script_tag(name:"last_modification", value:"2024-06-25 05:05:27 +0000 (Tue, 25 Jun 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-06-20 15:17:16 +0000 (Thu, 20 Jun 2024)");

  script_name("Mageia: Security Advisory (MGASA-2024-0233)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA9");

  script_xref(name:"Advisory-ID", value:"MGASA-2024-0233");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2024-0233.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=33321");
  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2024/06/stable-channel-update-for-desktop_18.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'chromium-browser-stable' package(s) announced via the MGASA-2024-0233 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"High CVE-2024-6100: Type Confusion in V8. Reported by Seunghyun Lee
(@0x10n) participating in SSD Secure Disclosure's TyphoonPWN 2024 on
2024-06-04
High CVE-2024-6101: Inappropriate implementation in WebAssembly.
Reported by @ginggilBesel on 2024-05-31
High CVE-2024-6102: Out of bounds memory access in Dawn. Reported by
wgslfuzz on 2024-05-07
High CVE-2024-6103: Use after free in Dawn. Reported by wgslfuzz on
2024-06-04");

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

  if(!isnull(res = isrpmvuln(pkg:"chromium-browser", rpm:"chromium-browser~126.0.6478.114~1.mga9.tainted", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-browser-stable", rpm:"chromium-browser-stable~126.0.6478.114~1.mga9.tainted", rls:"MAGEIA9"))) {
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
