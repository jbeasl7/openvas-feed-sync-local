# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.841199");
  script_cve_id("CVE-2008-5983", "CVE-2010-1634", "CVE-2010-2089", "CVE-2011-4944", "CVE-2012-0845", "CVE-2012-1150", "CVE-2012-2135");
  script_tag(name:"creation_date", value:"2012-10-26 04:20:43 +0000 (Fri, 26 Oct 2012)");
  script_version("2024-02-02T05:06:04+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:04 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-1616-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(10\.04\ LTS|11\.04)");

  script_xref(name:"Advisory-ID", value:"USN-1616-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1616-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python3.1' package(s) announced via the USN-1616-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that Python would prepend an empty string to sys.path
under certain circumstances. A local attacker with write access to the
current working directory could exploit this to execute arbitrary code.
This issue only affected Ubuntu 10.04 LTS. (CVE-2008-5983)

It was discovered that the audioop module did not correctly perform input
validation. If a user or automatated system were tricked into opening a
crafted audio file, an attacker could cause a denial of service via
application crash. These issues only affected Ubuntu 10.04 LTS.
(CVE-2010-1634, CVE-2010-2089)

It was discovered that Python distutils contained a race condition when
creating the ~/.pypirc file. A local attacker could exploit this to obtain
sensitive information. (CVE-2011-4944)

It was discovered that SimpleXMLRPCServer did not properly validate its
input when handling HTTP POST requests. A remote attacker could exploit
this to cause a denial of service via excessive CPU utilization.
(CVE-2012-0845)

It was discovered that Python was susceptible to hash algorithm attacks.
An attacker could cause a denial of service under certain circumstances.
This update adds the '-R' command line option and honors setting the
PYTHONHASHSEED environment variable to 'random' to salt str and datetime
objects with an unpredictable value. (CVE-2012-1150)

Serhiy Storchaka discovered that the UTF16 decoder in Python did not
properly reset internal variables after error handling. An attacker could
exploit this to cause a denial of service via memory corruption.
(CVE-2012-2135)");

  script_tag(name:"affected", value:"'python3.1' package(s) on Ubuntu 10.04, Ubuntu 11.04.");

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

if(release == "UBUNTU10.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"python3.1", ver:"3.1.2-0ubuntu3.2", rls:"UBUNTU10.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python3.1-minimal", ver:"3.1.2-0ubuntu3.2", rls:"UBUNTU10.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU11.04") {

  if(!isnull(res = isdpkgvuln(pkg:"python3.1", ver:"3.1.3-1ubuntu1.2", rls:"UBUNTU11.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python3.1-minimal", ver:"3.1.3-1ubuntu1.2", rls:"UBUNTU11.04"))) {
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
