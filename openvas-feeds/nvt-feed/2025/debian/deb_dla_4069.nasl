# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.1.2.2025.4069");
  script_cve_id("CVE-2023-28617", "CVE-2024-53920", "CVE-2025-1244");
  script_tag(name:"creation_date", value:"2025-02-28 04:05:20 +0000 (Fri, 28 Feb 2025)");
  script_version("2025-02-28T05:38:48+0000");
  script_tag(name:"last_modification", value:"2025-02-28 05:38:48 +0000 (Fri, 28 Feb 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-02-12 15:15:18 +0000 (Wed, 12 Feb 2025)");

  script_name("Debian: Security Advisory (DLA-4069-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB11");

  script_xref(name:"Advisory-ID", value:"DLA-4069-1");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2025/DLA-4069-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'emacs' package(s) announced via the DLA-4069-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"affected", value:"'emacs' package(s) on Debian 11.");

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

  if(!isnull(res = isdpkgvuln(pkg:"emacs", ver:"1:27.1+1-3.1+deb11u6", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"emacs-bin-common", ver:"1:27.1+1-3.1+deb11u6", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"emacs-common", ver:"1:27.1+1-3.1+deb11u6", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"emacs-el", ver:"1:27.1+1-3.1+deb11u6", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"emacs-gtk", ver:"1:27.1+1-3.1+deb11u6", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"emacs-lucid", ver:"1:27.1+1-3.1+deb11u6", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"emacs-nox", ver:"1:27.1+1-3.1+deb11u6", rls:"DEB11"))) {
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
