# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.841197");
  script_cve_id("CVE-2011-4944", "CVE-2012-0845", "CVE-2012-1150", "CVE-2012-2135");
  script_tag(name:"creation_date", value:"2012-10-26 04:14:22 +0000 (Fri, 26 Oct 2012)");
  script_version("2024-02-02T05:06:04+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:04 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:P");

  script_name("Ubuntu: Security Advisory (USN-1615-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(11\.04|11\.10|12\.04\ LTS|12\.10)");

  script_xref(name:"Advisory-ID", value:"USN-1615-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1615-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python3.2' package(s) announced via the USN-1615-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that Python distutils contained a race condition when
creating the ~/.pypirc file. A local attacker could exploit this to obtain
sensitive information. (CVE-2011-4944)

It was discovered that SimpleXMLRPCServer did not properly validate its
input when handling HTTP POST requests. A remote attacker could exploit
this to cause a denial of service via excessive CPU utilization. This issue
only affected Ubuntu 11.04 and 11.10. (CVE-2012-0845)

It was discovered that Python was susceptible to hash algorithm attacks.
An attacker could cause a denial of service under certain circumstances.
This update adds the '-R' command line option and honors setting the
PYTHONHASHSEED environment variable to 'random' to salt str and datetime
objects with an unpredictable value. This issue only affected Ubuntu 11.04
and 11.10. (CVE-2012-1150)

Serhiy Storchaka discovered that the UTF16 decoder in Python did not
properly reset internal variables after error handling. An attacker could
exploit this to cause a denial of service via memory corruption. This issue
did not affect Ubuntu 12.10. (CVE-2012-2135)");

  script_tag(name:"affected", value:"'python3.2' package(s) on Ubuntu 11.04, Ubuntu 11.10, Ubuntu 12.04, Ubuntu 12.10.");

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

if(release == "UBUNTU11.04") {

  if(!isnull(res = isdpkgvuln(pkg:"python3.2", ver:"3.2-1ubuntu1.2", rls:"UBUNTU11.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python3.2-minimal", ver:"3.2-1ubuntu1.2", rls:"UBUNTU11.04"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU11.10") {

  if(!isnull(res = isdpkgvuln(pkg:"python3.2", ver:"3.2.2-0ubuntu1.1", rls:"UBUNTU11.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python3.2-minimal", ver:"3.2.2-0ubuntu1.1", rls:"UBUNTU11.10"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU12.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"python3.2", ver:"3.2.3-0ubuntu3.2", rls:"UBUNTU12.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python3.2-minimal", ver:"3.2.3-0ubuntu3.2", rls:"UBUNTU12.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU12.10") {

  if(!isnull(res = isdpkgvuln(pkg:"python3.2", ver:"3.2.3-6ubuntu3.1", rls:"UBUNTU12.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python3.2-minimal", ver:"3.2.3-6ubuntu3.1", rls:"UBUNTU12.10"))) {
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
