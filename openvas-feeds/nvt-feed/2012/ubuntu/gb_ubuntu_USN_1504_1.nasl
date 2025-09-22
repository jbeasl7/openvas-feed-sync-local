# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.841082");
  script_cve_id("CVE-2010-5076", "CVE-2011-3193", "CVE-2011-3194");
  script_tag(name:"creation_date", value:"2012-07-16 06:23:40 +0000 (Mon, 16 Jul 2012)");
  script_version("2024-02-02T05:06:04+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:04 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-1504-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(10\.04\ LTS|11\.04)");

  script_xref(name:"Advisory-ID", value:"USN-1504-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1504-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'qt4-x11' package(s) announced via the USN-1504-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that Qt did not properly handle wildcard domain names or
IP addresses in the Common Name field of X.509 certificates. An attacker
could exploit this to perform a machine-in-the-middle attack to view sensitive
information or alter encrypted communications. This issue only affected
Ubuntu 10.04 LTS. (CVE-2010-5076)

A heap-based buffer overflow was discovered in the HarfBuzz module. If a
user were tricked into opening a crafted font file in a Qt application,
an attacker could cause a denial of service or possibly execute arbitrary
code with the privileges of the user invoking the program. (CVE-2011-3193)

It was discovered that Qt did not properly handle greyscale TIFF images.
If a Qt application could be made to process a crafted TIFF file, an
attacker could cause a denial of service. (CVE-2011-3194)");

  script_tag(name:"affected", value:"'qt4-x11' package(s) on Ubuntu 10.04, Ubuntu 11.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libqt4-network", ver:"4:4.6.2-0ubuntu5.4", rls:"UBUNTU10.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libqtgui4", ver:"4:4.6.2-0ubuntu5.4", rls:"UBUNTU10.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libqt4-network", ver:"4:4.7.2-0ubuntu6.4", rls:"UBUNTU11.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libqtgui4", ver:"4:4.7.2-0ubuntu6.4", rls:"UBUNTU11.04"))) {
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
