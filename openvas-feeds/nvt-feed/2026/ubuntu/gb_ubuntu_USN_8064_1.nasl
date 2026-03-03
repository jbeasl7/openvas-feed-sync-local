# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2026.8064.1");
  script_cve_id("CVE-2018-20802");
  script_tag(name:"creation_date", value:"2026-03-02 04:35:29 +0000 (Mon, 02 Mar 2026)");
  script_version("2026-03-02T05:55:30+0000");
  script_tag(name:"last_modification", value:"2026-03-02 05:55:30 +0000 (Mon, 02 Mar 2026)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-11-29 21:24:19 +0000 (Sun, 29 Nov 2020)");

  script_name("Ubuntu: Security Advisory (USN-8064-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(14\.04\ LTS|16\.04\ LTS|18\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-8064-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-8064-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'mongodb' package(s) announced via the USN-8064-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Eliot Horowitz discovered that MongoDB may fail to validate some instances
of malformed BSON. A remote attacker could possibly use this issue to cause
MongoDB to crash, resulting in a denial of service. This issue only
affected Ubuntu 14.04 LTS. (CVE-2015-1609)

It was discovered that MongoDB read raw permissions from .dbshell history
files. A local attacker could possibly use this issue to obtain sensitive
information. This issue only affected Ubuntu 14.04 LTS and Ubuntu 16.04
LTS. (CVE-2016-6494)

Travis Brown discovered that MongoDB may be unable to parse specially
crafted UTF-8 strings in BSON requests. A remote attacker could possibly
use this issue to cause MongoDB to crash, resulting in a denial of service.
This issue only affected Ubuntu 18.04 LTS. (CVE-2018-20802)");

  script_tag(name:"affected", value:"'mongodb' package(s) on Ubuntu 14.04, Ubuntu 16.04, Ubuntu 18.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"mongodb", ver:"1:2.4.9-1ubuntu2+esm2", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mongodb-server", ver:"1:2.4.9-1ubuntu2+esm2", rls:"UBUNTU14.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"mongodb", ver:"1:2.6.10-0ubuntu1+esm2", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mongodb-server", ver:"1:2.6.10-0ubuntu1+esm2", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU18.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"mongodb", ver:"1:3.6.3-0ubuntu1.4+esm1", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mongodb-server", ver:"1:3.6.3-0ubuntu1.4+esm1", rls:"UBUNTU18.04 LTS"))) {
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
