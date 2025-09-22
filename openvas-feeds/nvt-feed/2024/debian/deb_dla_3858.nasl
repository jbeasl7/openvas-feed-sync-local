# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.1.2.2024.3858");
  script_cve_id("CVE-2021-33621", "CVE-2022-28739", "CVE-2023-28755", "CVE-2023-28756", "CVE-2023-36617", "CVE-2024-27280", "CVE-2024-27281", "CVE-2024-27282");
  script_tag(name:"creation_date", value:"2024-09-03 04:23:37 +0000 (Tue, 03 Sep 2024)");
  script_version("2024-09-03T06:26:22+0000");
  script_tag(name:"last_modification", value:"2024-09-03 06:26:22 +0000 (Tue, 03 Sep 2024)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-11-22 21:04:21 +0000 (Tue, 22 Nov 2022)");

  script_name("Debian: Security Advisory (DLA-3858-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB11");

  script_xref(name:"Advisory-ID", value:"DLA-3858-1");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2024/DLA-3858-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'ruby2.7' package(s) announced via the DLA-3858-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"affected", value:"'ruby2.7' package(s) on Debian 11.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libruby2.7", ver:"2.7.4-1+deb11u2", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ruby2.7", ver:"2.7.4-1+deb11u2", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ruby2.7-dev", ver:"2.7.4-1+deb11u2", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ruby2.7-doc", ver:"2.7.4-1+deb11u2", rls:"DEB11"))) {
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
