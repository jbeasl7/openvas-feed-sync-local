# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.840957");
  script_cve_id("CVE-2011-3658", "CVE-2012-0455", "CVE-2012-0456", "CVE-2012-0457", "CVE-2012-0458", "CVE-2012-0461", "CVE-2012-0464");
  script_tag(name:"creation_date", value:"2012-03-22 05:13:07 +0000 (Thu, 22 Mar 2012)");
  script_version("2024-02-02T05:06:04+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:04 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-1401-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(10\.04\ LTS|10\.10)");

  script_xref(name:"Advisory-ID", value:"USN-1401-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1401-1");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/953736");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'xulrunner-1.9.2' package(s) announced via the USN-1401-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that a flaw in the Mozilla SVG implementation could
result in an out-of-bounds memory access if SVG elements were removed
during a DOMAttrModified event handler. If the user were tricked into
opening a specially crafted page, an attacker could exploit this to cause a
denial of service via application crash. (CVE-2011-3658)

Atte Kettunen discovered a use-after-free vulnerability in the Gecko
Rendering Engine's handling of SVG animations. An attacker could
potentially exploit this to execute arbitrary code with the privileges of
the user invoking the Xulrunner based application. (CVE-2012-0457)

Atte Kettunen discovered an out of bounds read vulnerability in the Gecko
Rendering Engine's handling of SVG Filters. An attacker could potentially
exploit this to make data from the user's memory accessible to the page
content. (CVE-2012-0456)

Soroush Dalili discovered that the Gecko Rendering Engine did not
adequately protect against dropping JavaScript links onto a frame. A remote
attacker could, through cross-site scripting (XSS), exploit this to modify
the contents of the frame or steal confidential data. (CVE-2012-0455)

Mariusz Mlynski discovered that the Home button accepted JavaScript links
to set the browser Home page. An attacker could use this vulnerability to
get the script URL loaded in the privileged about:sessionrestore context.
(CVE-2012-0458)

Bob Clary, Vincenzo Iozzo, and Willem Pinckaers discovered memory safety
issues affecting Firefox. If the user were tricked into opening a specially
crafted page, an attacker could exploit these to cause a denial of service
via application crash, or potentially execute code with the privileges of
the user invoking Firefox. (CVE-2012-0461, CVE-2012-0464)");

  script_tag(name:"affected", value:"'xulrunner-1.9.2' package(s) on Ubuntu 10.04, Ubuntu 10.10.");

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

  if(!isnull(res = isdpkgvuln(pkg:"xulrunner-1.9.2", ver:"1.9.2.28+build1+nobinonly-0ubuntu0.10.04.1", rls:"UBUNTU10.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU10.10") {

  if(!isnull(res = isdpkgvuln(pkg:"xulrunner-1.9.2", ver:"1.9.2.28+build1+nobinonly-0ubuntu0.10.10.1", rls:"UBUNTU10.10"))) {
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
