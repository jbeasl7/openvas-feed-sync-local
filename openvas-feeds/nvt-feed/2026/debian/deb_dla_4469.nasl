# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.1.2.2026.4469");
  script_cve_id("CVE-2026-25068");
  script_tag(name:"creation_date", value:"2026-02-06 04:35:58 +0000 (Fri, 06 Feb 2026)");
  script_version("2026-02-06T05:56:14+0000");
  script_tag(name:"last_modification", value:"2026-02-06 05:56:14 +0000 (Fri, 06 Feb 2026)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Debian: Security Advisory (DLA-4469-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB11");

  script_xref(name:"Advisory-ID", value:"DLA-4469-1");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2026/DLA-4469-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'alsa-lib' package(s) announced via the DLA-4469-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"affected", value:"'alsa-lib' package(s) on Debian 11.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libasound2", ver:"1.2.4-1.1+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libasound2-data", ver:"1.2.4-1.1+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libasound2-dev", ver:"1.2.4-1.1+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libasound2-doc", ver:"1.2.4-1.1+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libasound2-plugin-smixer", ver:"1.2.4-1.1+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libasound2-udeb", ver:"1.2.4-1.1+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libatopology-dev", ver:"1.2.4-1.1+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libatopology2", ver:"1.2.4-1.1+deb11u1", rls:"DEB11"))) {
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
