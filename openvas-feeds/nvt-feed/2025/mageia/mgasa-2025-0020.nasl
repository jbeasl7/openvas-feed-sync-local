# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2025.0020");
  script_cve_id("CVE-2024-7025", "CVE-2024-9369", "CVE-2024-9370", "CVE-2024-9602", "CVE-2024-9603", "CVE-2024-9954", "CVE-2024-9955", "CVE-2024-9956", "CVE-2024-9957", "CVE-2024-9958", "CVE-2024-9959", "CVE-2024-9960", "CVE-2024-9961", "CVE-2024-9962", "CVE-2024-9963", "CVE-2024-9964", "CVE-2024-9965", "CVE-2024-9966");
  script_tag(name:"creation_date", value:"2025-01-23 04:12:28 +0000 (Thu, 23 Jan 2025)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-01-02 17:55:20 +0000 (Thu, 02 Jan 2025)");

  script_name("Mageia: Security Advisory (MGASA-2025-0020)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA9");

  script_xref(name:"Advisory-ID", value:"MGASA-2025-0020");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2025-0020.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=33609");
  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2024/10/stable-channel-update-for-desktop.html");
  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2024/10/stable-channel-update-for-desktop_15.html");
  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2024/10/stable-channel-update-for-desktop_22.html");
  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2024/10/stable-channel-update-for-desktop_29.html");
  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2024/10/stable-channel-update-for-desktop_8.html");
  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2024/11/stable-channel-update-for-desktop.html");
  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2024/11/stable-channel-update-for-desktop_12.html");
  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2024/11/stable-channel-update-for-desktop_19.html");
  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2024/12/stable-channel-update-for-desktop.html");
  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2024/12/stable-channel-update-for-desktop_10.html");
  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2024/12/stable-channel-update-for-desktop_18.html");
  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2025/01/stable-channel-update-for-desktop.html");
  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2025/01/stable-channel-update-for-desktop_14.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'chromium-browser-stable' package(s) announced via the MGASA-2025-0020 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Lot of CVEs were fixed by upstream since our current version, please see
the links.");

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

  if(!isnull(res = isrpmvuln(pkg:"chromium-browser", rpm:"chromium-browser~132.0.6834.84~1.mga9.tainted", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-browser-stable", rpm:"chromium-browser-stable~132.0.6834.84~1.mga9.tainted", rls:"MAGEIA9"))) {
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
