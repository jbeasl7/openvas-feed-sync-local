# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.843257");
  script_cve_id("CVE-2014-8501", "CVE-2014-9939", "CVE-2016-2226", "CVE-2016-4487", "CVE-2016-4488", "CVE-2016-4489", "CVE-2016-4490", "CVE-2016-4491", "CVE-2016-4492", "CVE-2016-4493", "CVE-2016-6131");
  script_tag(name:"creation_date", value:"2017-07-27 05:15:47 +0000 (Thu, 27 Jul 2017)");
  script_version("2024-02-02T05:06:06+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:06 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-03-22 19:12:00 +0000 (Wed, 22 Mar 2017)");

  script_name("Ubuntu: Security Advisory (USN-3367-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(14\.04\ LTS|16\.04\ LTS|17\.04)");

  script_xref(name:"Advisory-ID", value:"USN-3367-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3367-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'gdb' package(s) announced via the USN-3367-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Hanno Bock discovered that gdb incorrectly handled certain malformed AOUT
headers in PE executables. If a user or automated system were tricked into
processing a specially crafted binary, a remote attacker could use this
issue to cause gdb to crash, resulting in a denial of service, or possibly
execute arbitrary code. This issue only applied to Ubuntu 14.04 LTS.
(CVE-2014-8501)

It was discovered that gdb incorrectly handled printing bad bytes in Intel
Hex objects. If a user or automated system were tricked into processing a
specially crafted binary, a remote attacker could use this issue to cause
gdb to crash, resulting in a denial of service. This issue only applied to
Ubuntu 14.04 LTS. (CVE-2014-9939)

It was discovered that gdb incorrectly handled certain string operations.
If a user or automated system were tricked into processing a specially
crafted binary, a remote attacker could use this issue to cause gdb to
crash, resulting in a denial of service, or possibly execute arbitrary
code. This issue only applied to Ubuntu 14.04 LTS and Ubuntu 16.04 LTS.
(CVE-2016-2226)

It was discovered that gdb incorrectly handled parsing certain binaries. If
a user or automated system were tricked into processing a specially crafted
binary, a remote attacker could use this issue to cause gdb to crash,
resulting in a denial of service. This issue only applied to Ubuntu 14.04
LTS and Ubuntu 16.04 LTS. (CVE-2016-4487, CVE-2016-4488, CVE-2016-4489,
CVE-2016-4490, CVE-2016-4492, CVE-2016-4493, CVE-2016-6131)

It was discovered that gdb incorrectly handled parsing certain binaries. If
a user or automated system were tricked into processing a specially crafted
binary, a remote attacker could use this issue to cause gdb to crash,
resulting in a denial of service. (CVE-2016-4491)");

  script_tag(name:"affected", value:"'gdb' package(s) on Ubuntu 14.04, Ubuntu 16.04, Ubuntu 17.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"gdb", ver:"7.7.1-0ubuntu5~14.04.3", rls:"UBUNTU14.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"gdb", ver:"7.11.1-0ubuntu1~16.5", rls:"UBUNTU16.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"gdb", ver:"7.12.50.20170314-0ubuntu1.1", rls:"UBUNTU17.04"))) {
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
