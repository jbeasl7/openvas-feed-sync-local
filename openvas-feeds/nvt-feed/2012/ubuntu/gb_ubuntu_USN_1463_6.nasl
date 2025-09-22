# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.841059");
  script_cve_id("CVE-2011-3101", "CVE-2012-0441", "CVE-2012-1937", "CVE-2012-1938", "CVE-2012-1940", "CVE-2012-1941", "CVE-2012-1944", "CVE-2012-1945", "CVE-2012-1946", "CVE-2012-1947");
  script_tag(name:"creation_date", value:"2012-06-28 05:07:07 +0000 (Thu, 28 Jun 2012)");
  script_version("2024-02-02T05:06:04+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:04 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-1463-6)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU11\.04");

  script_xref(name:"Advisory-ID", value:"USN-1463-6");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1463-6");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/1007556");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'thunderbird' package(s) announced via the USN-1463-6 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-1463-1 fixed vulnerabilities in Firefox. This update provides the
corresponding fixes for Thunderbird.

Original advisory details:

 Jesse Ruderman, Igor Bukanov, Bill McCloskey, Christian Holler, Andrew
 McCreight, Olli Pettay, Boris Zbarsky, and Brian Bondy discovered memory
 safety issues affecting Firefox. If the user were tricked into opening a
 specially crafted page, an attacker could possibly exploit these to cause a
 denial of service via application crash, or potentially execute code with
 the privileges of the user invoking Firefox. (CVE-2012-1937, CVE-2012-1938)

 It was discovered that Mozilla's WebGL implementation exposed a bug in
 certain NVIDIA graphics drivers. The impact of this issue has not been
 disclosed at this time. (CVE-2011-3101)

 Adam Barth discovered that certain inline event handlers were not being
 blocked properly by the Content Security Policy's (CSP) inline-script
 blocking feature. Web applications relying on this feature of CSP to
 protect against cross-site scripting (XSS) were not fully protected. With
 cross-site scripting vulnerabilities, if a user were tricked into viewing a
 specially crafted page, a remote attacker could exploit this to modify the
 contents, or steal confidential data, within the same domain.
 (CVE-2012-1944)

 Paul Stone discovered that a viewed HTML page hosted on a Windows or Samba
 share could load Windows shortcut files (.lnk) in the same share. These
 shortcut files could then link to arbitrary locations on the local file
 system of the individual loading the HTML page. An attacker could
 potentially use this vulnerability to show the contents of these linked
 files or directories in an iframe, resulting in information disclosure.
 (CVE-2012-1945)

 Arthur Gerkis discovered a use-after-free vulnerability while
 replacing/inserting a node in a document. If the user were tricked into
 opening a specially crafted page, an attacker could possibly exploit this
 to cause a denial of service via application crash, or potentially execute
 code with the privileges of the user invoking Firefox. (CVE-2012-1946)

 Kaspar Brand discovered a vulnerability in how the Network Security
 Services (NSS) ASN.1 decoder handles zero length items. If the user were
 tricked into opening a specially crafted page, an attacker could possibly
 exploit this to cause a denial of service via application crash.
 (CVE-2012-0441)

 Abhishek Arya discovered two buffer overflow and one use-after-free
 vulnerabilities. If the user were tricked into opening a specially crafted
 page, an attacker could possibly exploit these to cause a denial of service
 via application crash, or potentially execute code with the privileges of
 the user invoking Firefox. (CVE-2012-1940, CVE-2012-1941, CVE-2012-1947)");

  script_tag(name:"affected", value:"'thunderbird' package(s) on Ubuntu 11.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"thunderbird", ver:"13.0.1+build1-0ubuntu0.11.04.1", rls:"UBUNTU11.04"))) {
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
