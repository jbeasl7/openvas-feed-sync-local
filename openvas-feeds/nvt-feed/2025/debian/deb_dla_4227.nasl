# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.1.2.2025.4227");
  script_cve_id("CVE-2022-2119", "CVE-2022-2120", "CVE-2024-47796", "CVE-2025-2357", "CVE-2025-25472", "CVE-2025-25474", "CVE-2025-25475");
  script_tag(name:"creation_date", value:"2025-06-25 04:11:27 +0000 (Wed, 25 Jun 2025)");
  script_version("2025-06-25T05:41:02+0000");
  script_tag(name:"last_modification", value:"2025-06-25 05:41:02 +0000 (Wed, 25 Jun 2025)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-03-17 02:15:13 +0000 (Mon, 17 Mar 2025)");

  script_name("Debian: Security Advisory (DLA-4227-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB11");

  script_xref(name:"Advisory-ID", value:"DLA-4227-1");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2025/DLA-4227-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'dcmtk' package(s) announced via the DLA-4227-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"affected", value:"'dcmtk' package(s) on Debian 11.");

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

  if(!isnull(res = isdpkgvuln(pkg:"dcmtk", ver:"3.6.5-1+deb11u4", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dcmtk-doc", ver:"3.6.5-1+deb11u4", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libdcmtk-dev", ver:"3.6.5-1+deb11u4", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libdcmtk15", ver:"3.6.5-1+deb11u4", rls:"DEB11"))) {
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
