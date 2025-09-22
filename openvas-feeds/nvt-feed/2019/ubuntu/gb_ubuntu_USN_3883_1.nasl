# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.843900");
  script_cve_id("CVE-2018-10119", "CVE-2018-10120", "CVE-2018-10583", "CVE-2018-11790", "CVE-2018-16858");
  script_tag(name:"creation_date", value:"2019-02-07 03:03:44 +0000 (Thu, 07 Feb 2019)");
  script_version("2024-02-02T05:06:07+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:07 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-03-25 18:29:00 +0000 (Mon, 25 Mar 2019)");

  script_name("Ubuntu: Security Advisory (USN-3883-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(14\.04\ LTS|16\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-3883-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3883-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libreoffice' package(s) announced via the USN-3883-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that LibreOffice incorrectly handled certain document
files. If a user were tricked into opening a specially crafted document, a
remote attacker could cause LibreOffice to crash, and possibly execute
arbitrary code. (CVE-2018-10119, CVE-2018-10120, CVE-2018-11790)

It was discovered that LibreOffice incorrectly handled embedded SMB
connections in document files. If a user were tricked in to opening a
specially crafted document, a remote attacker could possibly exploit this
to obtain sensitive information. (CVE-2018-10583)

Alex Infuhr discovered that LibreOffice incorrectly handled embedded
scripts in document files. If a user were tricked into opening a specially
crafted document, a remote attacker could possibly execute arbitrary code.
(CVE-2018-16858)");

  script_tag(name:"affected", value:"'libreoffice' package(s) on Ubuntu 14.04, Ubuntu 16.04.");

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

if(release == "UBUNTU14.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-core", ver:"1:4.2.8-0ubuntu5.5", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU16.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-core", ver:"1:5.1.6~rc2-0ubuntu1~xenial6", rls:"UBUNTU16.04 LTS"))) {
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
