# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.842119");
  script_cve_id("CVE-2015-0819", "CVE-2015-0820", "CVE-2015-0821", "CVE-2015-0822", "CVE-2015-0823", "CVE-2015-0824", "CVE-2015-0825", "CVE-2015-0826", "CVE-2015-0827");
  script_tag(name:"creation_date", value:"2015-03-10 05:33:44 +0000 (Tue, 10 Mar 2015)");
  script_version("2024-10-23T05:05:58+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:58 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Ubuntu: Security Advisory (USN-2505-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(12\.04\ LTS|14\.04\ LTS|14\.10)");

  script_xref(name:"Advisory-ID", value:"USN-2505-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2505-2");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/1425972");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/1429115");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'firefox' package(s) announced via the USN-2505-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-2505-1 fixed vulnerabilities in Firefox. This update removed the
deprecated '-remote' command-line switch that some older software still
depends on. This update fixes the problem.

We apologize for the inconvenience.

Original advisory details:

 Matthew Noorenberghe discovered that allowlisted Mozilla domains could
 make UITour API calls from background tabs. If one of these domains were
 compromised and open in a background tab, an attacker could potentially
 exploit this to conduct clickjacking attacks. (CVE-2015-0819)

 Jan de Mooij discovered an issue that affects content using the Caja
 Compiler. If web content loads specially crafted code, this could be used
 to bypass sandboxing security measures provided by Caja. (CVE-2015-0820)

 Armin Razmdjou discovered that opening hyperlinks with specific mouse
 and key combinations could allow a Chrome privileged URL to be opened
 without context restrictions being preserved. If a user were tricked in to
 opening a specially crafted website, an attacker could potentially exploit
 this to bypass security restrictions. (CVE-2015-0821)

 Armin Razmdjou discovered that contents of locally readable files could
 be made available via manipulation of form autocomplete in some
 circumstances. If a user were tricked in to opening a specially crafted
 website, an attacker could potentially exploit this to obtain sensitive
 information. (CVE-2015-0822)

 Atte Kettunen discovered a use-after-free in the OpenType Sanitiser (OTS)
 in some circumstances. If a user were tricked in to opening a specially
 crafted website, an attacker could potentially exploit this to cause a
 denial of service via application crash. (CVE-2015-0823)

 Atte Kettunen discovered a crash when drawing images using Cairo in some
 circumstances. If a user were tricked in to opening a specially crafted
 website, an attacker could potentially exploit this to cause a denial of
 service. (CVE-2015-0824)

 Atte Kettunen discovered a buffer underflow during playback of MP3 files
 in some circumstances. If a user were tricked in to opening a specially
 crafted website, an attacker could potentially exploit this to obtain
 sensitive information. (CVE-2015-0825)

 Atte Kettunen discovered a buffer overflow during CSS restyling in some
 circumstances. If a user were tricked in to opening a specially crafted
 website, an attacker could potentially exploit this to cause a denial of
 service via application crash, or execute arbitrary code with the
 privileges of the user invoking Firefox. (CVE-2015-0826)

 Abhishek Arya discovered an out-of-bounds read and write when rendering
 SVG content in some circumstances. If a user were tricked in to opening
 a specially crafted website, an attacker could potentially exploit this
 to obtain sensitive information. (CVE-2015-0827)

 A buffer overflow was discovered in libstagefright during video playback
 in some circumstances. If a ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'firefox' package(s) on Ubuntu 12.04, Ubuntu 14.04, Ubuntu 14.10.");

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

if(release == "UBUNTU12.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"firefox", ver:"36.0.1+build2-0ubuntu0.12.04.1", rls:"UBUNTU12.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU14.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"firefox", ver:"36.0.1+build2-0ubuntu0.14.04.1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU14.10") {

  if(!isnull(res = isdpkgvuln(pkg:"firefox", ver:"36.0.1+build2-0ubuntu0.14.10.1", rls:"UBUNTU14.10"))) {
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
