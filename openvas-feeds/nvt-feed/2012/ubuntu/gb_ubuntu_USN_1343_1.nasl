# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.840939");
  script_cve_id("CVE-2011-3658", "CVE-2011-3660", "CVE-2011-3661", "CVE-2011-3663", "CVE-2011-3665");
  script_tag(name:"creation_date", value:"2012-03-16 05:21:11 +0000 (Fri, 16 Mar 2012)");
  script_version("2024-02-02T05:06:04+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:04 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-1343-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU11\.10");

  script_xref(name:"Advisory-ID", value:"USN-1343-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1343-1");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/909599");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'thunderbird' package(s) announced via the USN-1343-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Alexandre Poirot, Chris Blizzard, Kyle Huey, Scoobidiver, Christian Holler,
David Baron, Gary Kwong, Jim Blandy, Bob Clary, Jesse Ruderman, Marcia
Knous, and Rober Longson discovered several memory safety issues which
could possibly be exploited to crash Thunderbird or execute arbitrary code
as the user that invoked Thunderbird. (CVE-2011-3660)

Aki Helin discovered a crash in the YARR regular expression library that
could be triggered by javascript in web content. (CVE-2011-3661)

It was discovered that a flaw in the Mozilla SVG implementation could
result in an out-of-bounds memory access if SVG elements were removed
during a DOMAttrModified event handler. An attacker could potentially
exploit this vulnerability to crash Thunderbird. (CVE-2011-3658)

Mario Heiderich discovered it was possible to use SVG animation accessKey
events to detect key strokes even when JavaScript was disabled. A malicious
web page could potentially exploit this to trick a user into interacting
with a prompt thinking it came from Thunderbird in a context where the user
believed scripting was disabled. (CVE-2011-3663)

It was discovered that it was possible to crash Thunderbird when scaling an
OGG <video> element to extreme sizes. (CVE-2011-3665)");

  script_tag(name:"affected", value:"'thunderbird' package(s) on Ubuntu 11.10.");

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

if(release == "UBUNTU11.10") {

  if(!isnull(res = isdpkgvuln(pkg:"thunderbird", ver:"9.0+build2-0ubuntu0.11.10.1", rls:"UBUNTU11.10"))) {
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
