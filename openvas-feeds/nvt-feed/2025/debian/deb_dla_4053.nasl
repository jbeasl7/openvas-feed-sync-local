# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.1.2.2025.4053");
  script_cve_id("CVE-2021-41160", "CVE-2022-24883", "CVE-2022-39282", "CVE-2022-39283", "CVE-2022-39316", "CVE-2022-39318", "CVE-2022-39319", "CVE-2022-39347", "CVE-2022-41877", "CVE-2023-39350", "CVE-2023-39351", "CVE-2023-39352", "CVE-2023-39353", "CVE-2023-39354", "CVE-2023-39356", "CVE-2023-40181", "CVE-2023-40186", "CVE-2023-40188", "CVE-2023-40567", "CVE-2023-40569", "CVE-2023-40589", "CVE-2024-22211", "CVE-2024-32039", "CVE-2024-32040", "CVE-2024-32041", "CVE-2024-32458", "CVE-2024-32459", "CVE-2024-32460", "CVE-2024-32658", "CVE-2024-32659", "CVE-2024-32660", "CVE-2024-32661");
  script_tag(name:"creation_date", value:"2025-02-17 04:05:10 +0000 (Mon, 17 Feb 2025)");
  script_version("2025-02-17T05:38:47+0000");
  script_tag(name:"last_modification", value:"2025-02-17 05:38:47 +0000 (Mon, 17 Feb 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-02-04 17:42:16 +0000 (Tue, 04 Feb 2025)");

  script_name("Debian: Security Advisory (DLA-4053-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB11");

  script_xref(name:"Advisory-ID", value:"DLA-4053-1");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2025/DLA-4053-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'freerdp2' package(s) announced via the DLA-4053-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"affected", value:"'freerdp2' package(s) on Debian 11.");

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

if(release == "DEB11") {

  if(!isnull(res = isdpkgvuln(pkg:"freerdp2-dev", ver:"2.3.0+dfsg1-2+deb11u2", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"freerdp2-shadow-x11", ver:"2.3.0+dfsg1-2+deb11u2", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"freerdp2-wayland", ver:"2.3.0+dfsg1-2+deb11u2", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"freerdp2-x11", ver:"2.3.0+dfsg1-2+deb11u2", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libfreerdp-client2-2", ver:"2.3.0+dfsg1-2+deb11u2", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libfreerdp-server2-2", ver:"2.3.0+dfsg1-2+deb11u2", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libfreerdp-shadow-subsystem2-2", ver:"2.3.0+dfsg1-2+deb11u2", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libfreerdp-shadow2-2", ver:"2.3.0+dfsg1-2+deb11u2", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libfreerdp2-2", ver:"2.3.0+dfsg1-2+deb11u2", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libuwac0-0", ver:"2.3.0+dfsg1-2+deb11u2", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libuwac0-dev", ver:"2.3.0+dfsg1-2+deb11u2", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libwinpr-tools2-2", ver:"2.3.0+dfsg1-2+deb11u2", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libwinpr2-2", ver:"2.3.0+dfsg1-2+deb11u2", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libwinpr2-dev", ver:"2.3.0+dfsg1-2+deb11u2", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"winpr-utils", ver:"2.3.0+dfsg1-2+deb11u2", rls:"DEB11"))) {
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
