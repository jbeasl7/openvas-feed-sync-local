# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.1.2.2024.3980");
  script_cve_id("CVE-2015-20107", "CVE-2020-10735", "CVE-2021-28861", "CVE-2021-29921", "CVE-2021-3426", "CVE-2021-3733", "CVE-2021-3737", "CVE-2021-4189", "CVE-2022-42919", "CVE-2022-45061", "CVE-2023-24329", "CVE-2023-27043", "CVE-2023-40217", "CVE-2023-6597", "CVE-2024-0397", "CVE-2024-0450", "CVE-2024-11168", "CVE-2024-4032", "CVE-2024-6232", "CVE-2024-6923", "CVE-2024-7592", "CVE-2024-8088", "CVE-2024-9287");
  script_tag(name:"creation_date", value:"2024-12-03 04:09:24 +0000 (Tue, 03 Dec 2024)");
  script_version("2024-12-04T05:05:48+0000");
  script_tag(name:"last_modification", value:"2024-12-04 05:05:48 +0000 (Wed, 04 Dec 2024)");
  script_tag(name:"cvss_base", value:"8.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:C/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-11-09 17:55:33 +0000 (Wed, 09 Nov 2022)");

  script_name("Debian: Security Advisory (DLA-3980-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB11");

  script_xref(name:"Advisory-ID", value:"DLA-3980-1");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2024/DLA-3980-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'python3.9' package(s) announced via the DLA-3980-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"affected", value:"'python3.9' package(s) on Debian 11.");

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

  if(!isnull(res = isdpkgvuln(pkg:"idle-python3.9", ver:"3.9.2-1+deb11u2", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libpython3.9", ver:"3.9.2-1+deb11u2", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libpython3.9-dbg", ver:"3.9.2-1+deb11u2", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libpython3.9-dev", ver:"3.9.2-1+deb11u2", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libpython3.9-minimal", ver:"3.9.2-1+deb11u2", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libpython3.9-stdlib", ver:"3.9.2-1+deb11u2", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libpython3.9-testsuite", ver:"3.9.2-1+deb11u2", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python3.9", ver:"3.9.2-1+deb11u2", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python3.9-dbg", ver:"3.9.2-1+deb11u2", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python3.9-dev", ver:"3.9.2-1+deb11u2", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python3.9-doc", ver:"3.9.2-1+deb11u2", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python3.9-examples", ver:"3.9.2-1+deb11u2", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python3.9-full", ver:"3.9.2-1+deb11u2", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python3.9-minimal", ver:"3.9.2-1+deb11u2", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python3.9-venv", ver:"3.9.2-1+deb11u2", rls:"DEB11"))) {
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
