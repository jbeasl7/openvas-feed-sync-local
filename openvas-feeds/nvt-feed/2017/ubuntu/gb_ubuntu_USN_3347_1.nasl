# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.843235");
  script_cve_id("CVE-2017-7526", "CVE-2017-9526");
  script_tag(name:"creation_date", value:"2017-07-14 10:25:04 +0000 (Fri, 14 Jul 2017)");
  script_version("2024-02-02T05:06:06+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:06 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-10-02 14:02:49 +0000 (Tue, 02 Oct 2018)");

  script_name("Ubuntu: Security Advisory (USN-3347-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(14\.04\ LTS|16\.04\ LTS|16\.10|17\.04)");

  script_xref(name:"Advisory-ID", value:"USN-3347-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3347-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libgcrypt11, libgcrypt20' package(s) announced via the USN-3347-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Daniel J. Bernstein, Joachim Breitner, Daniel Genkin, Leon Groot
Bruinderink, Nadia Heninger, Tanja Lange, Christine van Vredendaal, and
Yuval Yarom discovered that Libgcrypt was susceptible to an attack via
side channels. A local attacker could use this attack to recover RSA
private keys. (CVE-2017-7526)

It was discovered that Libgcrypt was susceptible to an attack via
side channels. A local attacker could use this attack to possibly recover
EdDSA private keys. This issue only applied to Ubuntu 16.04 LTS, Ubuntu
16.10 and Ubuntu 17.04. (CVE-2017-9526)");

  script_tag(name:"affected", value:"'libgcrypt11, libgcrypt20' package(s) on Ubuntu 14.04, Ubuntu 16.04, Ubuntu 16.10, Ubuntu 17.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libgcrypt11", ver:"1.5.3-2ubuntu4.5", rls:"UBUNTU14.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libgcrypt20", ver:"1.6.5-2ubuntu0.3", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU16.10") {

  if(!isnull(res = isdpkgvuln(pkg:"libgcrypt20", ver:"1.7.2-2ubuntu1.1", rls:"UBUNTU16.10"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU17.04") {

  if(!isnull(res = isdpkgvuln(pkg:"libgcrypt20", ver:"1.7.6-1ubuntu0.1", rls:"UBUNTU17.04"))) {
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
