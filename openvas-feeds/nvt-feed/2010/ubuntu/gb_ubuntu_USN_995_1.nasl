# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.840507");
  script_cve_id("CVE-2007-6720", "CVE-2009-0179", "CVE-2009-3995", "CVE-2009-3996", "CVE-2010-2546", "CVE-2010-2971");
  script_tag(name:"creation_date", value:"2010-10-01 14:10:21 +0000 (Fri, 01 Oct 2010)");
  script_version("2024-02-02T05:06:04+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:04 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-995-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(8\.04\ LTS|9\.04|9\.10)");

  script_xref(name:"Advisory-ID", value:"USN-995-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-995-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libmikmod' package(s) announced via the USN-995-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that libMikMod incorrectly handled songs with different
channel counts. If a user were tricked into opening a crafted song file,
an attacker could cause a denial of service. (CVE-2007-6720)

It was discovered that libMikMod incorrectly handled certain malformed XM
files. If a user were tricked into opening a crafted XM file, an attacker
could cause a denial of service. (CVE-2009-0179)

It was discovered that libMikMod incorrectly handled certain malformed
Impulse Tracker files. If a user were tricked into opening a crafted
Impulse Tracker file, an attacker could cause a denial of service or
possibly execute arbitrary code with the privileges of the user invoking
the program. (CVE-2009-3995, CVE-2010-2546, CVE-2010-2971)

It was discovered that libMikMod incorrectly handled certain malformed
Ultratracker files. If a user were tricked into opening a crafted
Ultratracker file, an attacker could cause a denial of service or possibly
execute arbitrary code with the privileges of the user invoking the
program. (CVE-2009-3996)");

  script_tag(name:"affected", value:"'libmikmod' package(s) on Ubuntu 8.04, Ubuntu 9.04, Ubuntu 9.10.");

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

if(release == "UBUNTU8.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"libmikmod2", ver:"3.1.11-6ubuntu3.8.04.1", rls:"UBUNTU8.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU9.04") {

  if(!isnull(res = isdpkgvuln(pkg:"libmikmod2", ver:"3.1.11-6ubuntu3.9.04.1", rls:"UBUNTU9.04"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU9.10") {

  if(!isnull(res = isdpkgvuln(pkg:"libmikmod2", ver:"3.1.11-6ubuntu4.1", rls:"UBUNTU9.10"))) {
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
