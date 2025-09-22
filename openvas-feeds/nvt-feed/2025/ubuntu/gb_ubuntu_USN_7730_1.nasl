# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2025.7730.1");
  script_cve_id("CVE-2017-17689", "CVE-2019-10732");
  script_tag(name:"creation_date", value:"2025-09-04 04:07:10 +0000 (Thu, 04 Sep 2025)");
  script_version("2025-09-04T05:39:49+0000");
  script_tag(name:"last_modification", value:"2025-09-04 05:39:49 +0000 (Thu, 04 Sep 2025)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-04-09 18:14:05 +0000 (Tue, 09 Apr 2019)");

  script_name("Ubuntu: Security Advisory (USN-7730-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU18\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-7730-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-7730-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kf5-messagelib' package(s) announced via the USN-7730-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Damian Poddebniak, Christian Dresen, Jens Muller, Fabian Ising,
Sebastian Schinzel, Simon Friedberger, Juraj Somorovsky, and Jorg
Schwenk discovered that PIM Messagelib could be made to leak the plaintext
of S/MIME encrypted emails when retrieving external content in emails.
Under certain configurations, if a user were tricked into opening a
specially crafted email using an application linked against PIM Messagelib,
an attacker could possibly use this issue to obtain the plaintext of an
encrypted email. This update mitigates the issue by preventing automatic
loading of external content. (CVE-2017-17689)

Jens Muller, Marcus Brinkmann, Damian Poddebniak, Sebastian Schinzel,
and Jorg Schwenk discovered that PIM Messagelib could be made to leak the
plaintext of S/MIME or PGP encrypted emails. If a user were tricked into
replying to a specially crafted email using an application linked
against PIM Messagelib, an attacker could possibly use this issue to obtain
the plaintext of an encrypted email. (CVE-2019-10732)");

  script_tag(name:"affected", value:"'kf5-messagelib' package(s) on Ubuntu 18.04.");

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

if(release == "UBUNTU18.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"libkf5messageviewer5abi4", ver:"4:17.12.3-0ubuntu3+esm1", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libkf5mimetreeparser5abi2", ver:"4:17.12.3-0ubuntu3+esm1", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libkf5templateparser5abi2", ver:"4:17.12.3-0ubuntu3+esm1", rls:"UBUNTU18.04 LTS"))) {
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
