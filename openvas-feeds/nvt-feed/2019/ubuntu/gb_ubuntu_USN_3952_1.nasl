# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.843983");
  script_cve_id("CVE-2018-16877", "CVE-2018-16878", "CVE-2019-3885");
  script_tag(name:"creation_date", value:"2019-04-24 02:00:54 +0000 (Wed, 24 Apr 2019)");
  script_version("2024-02-02T05:06:07+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:07 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-04-22 13:57:42 +0000 (Mon, 22 Apr 2019)");

  script_name("Ubuntu: Security Advisory (USN-3952-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(16\.04\ LTS|18\.04\ LTS|18\.10|19\.04)");

  script_xref(name:"Advisory-ID", value:"USN-3952-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3952-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'pacemaker' package(s) announced via the USN-3952-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Jan Pokorny discovered that Pacemaker incorrectly handled client-server
authentication. A local attacker could possibly use this issue to escalate
privileges. (CVE-2018-16877)

Jan Pokorny discovered that Pacemaker incorrectly handled certain
verifications. A local attacker could possibly use this issue to cause a
denial of service. (CVE-2018-16878)

Jan Pokorny discovered that Pacemaker incorrectly handled certain memory
operations. A local attacker could possibly use this issue to obtain
sensitive information in log outputs. This issue only applied to Ubuntu
18.04 LTS, Ubuntu 18.10, and Ubuntu 19.04. (CVE-2019-3885)");

  script_tag(name:"affected", value:"'pacemaker' package(s) on Ubuntu 16.04, Ubuntu 18.04, Ubuntu 18.10, Ubuntu 19.04.");

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

if(release == "UBUNTU16.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"pacemaker", ver:"1.1.14-2ubuntu1.6", rls:"UBUNTU16.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"pacemaker", ver:"1.1.18-0ubuntu1.1", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU18.10") {

  if(!isnull(res = isdpkgvuln(pkg:"pacemaker", ver:"1.1.18-2ubuntu1.18.10.1", rls:"UBUNTU18.10"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU19.04") {

  if(!isnull(res = isdpkgvuln(pkg:"pacemaker", ver:"1.1.18-2ubuntu1.19.04.1", rls:"UBUNTU19.04"))) {
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
