# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2026.8105.1");
  script_cve_id("CVE-2026-22851", "CVE-2026-22852", "CVE-2026-22853", "CVE-2026-22854", "CVE-2026-22855", "CVE-2026-22856", "CVE-2026-22857", "CVE-2026-22858", "CVE-2026-22859", "CVE-2026-23530", "CVE-2026-23531", "CVE-2026-23532", "CVE-2026-23533", "CVE-2026-23534", "CVE-2026-23732", "CVE-2026-23883", "CVE-2026-23884", "CVE-2026-25941", "CVE-2026-25942", "CVE-2026-25952", "CVE-2026-25953", "CVE-2026-25954", "CVE-2026-25955", "CVE-2026-25959", "CVE-2026-25997", "CVE-2026-26271", "CVE-2026-26955", "CVE-2026-26965", "CVE-2026-26986", "CVE-2026-27015", "CVE-2026-27950", "CVE-2026-27951");
  script_tag(name:"creation_date", value:"2026-03-19 04:39:53 +0000 (Thu, 19 Mar 2026)");
  script_version("2026-03-19T05:56:32+0000");
  script_tag(name:"last_modification", value:"2026-03-19 05:56:32 +0000 (Thu, 19 Mar 2026)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2026-02-27 14:57:09 +0000 (Fri, 27 Feb 2026)");

  script_name("Ubuntu: Security Advisory (USN-8105-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(24\.04\ LTS|25\.10)");

  script_xref(name:"Advisory-ID", value:"USN-8105-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-8105-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'freerdp3' package(s) announced via the USN-8105-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that FreeRDP incorrectly handled certain RDP packets. A
remote attacker could use this issue to cause FreeRDP to crash, resulting
in a denial of service, or possibly execute arbitrary code.");

  script_tag(name:"affected", value:"'freerdp3' package(s) on Ubuntu 24.04, Ubuntu 25.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

release = dpkg_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "UBUNTU24.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"libfreerdp3-3", ver:"3.5.1+dfsg1-0ubuntu1.4", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU25.10") {

  if(!isnull(res = isdpkgvuln(pkg:"libfreerdp3-3", ver:"3.16.0+dfsg-2ubuntu0.3", rls:"UBUNTU25.10"))) {
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
