# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.842512");
  script_cve_id("CVE-2015-4513", "CVE-2015-4514", "CVE-2015-4515", "CVE-2015-4518", "CVE-2015-7181", "CVE-2015-7182", "CVE-2015-7183", "CVE-2015-7187", "CVE-2015-7188", "CVE-2015-7189", "CVE-2015-7193", "CVE-2015-7194", "CVE-2015-7195", "CVE-2015-7196", "CVE-2015-7197", "CVE-2015-7198", "CVE-2015-7199", "CVE-2015-7200");
  script_tag(name:"creation_date", value:"2015-11-05 05:17:24 +0000 (Thu, 05 Nov 2015)");
  script_version("2024-02-02T05:06:05+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:05 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2015-11-05 15:41:35 +0000 (Thu, 05 Nov 2015)");

  script_name("Ubuntu: Security Advisory (USN-2785-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(12\.04\ LTS|14\.04\ LTS|15\.04|15\.10)");

  script_xref(name:"Advisory-ID", value:"USN-2785-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2785-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'firefox' package(s) announced via the USN-2785-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Christian Holler, David Major, Jesse Ruderman, Tyson Smith, Boris Zbarsky,
Randell Jesup, Olli Pettay, Karl Tomlinson, Jeff Walden, Gary Kwong,
Andrew McCreight, Georg Fritzsche, and Carsten Book discovered multiple
memory safety issues in Firefox. If a user were tricked in to opening a
specially crafted website, an attacker could potentially exploit these to
cause a denial of service via application crash, or execute arbitrary
code with the privileges of the user invoking Firefox. (CVE-2015-4513,
CVE-2015-4514)

Tim Brown discovered that Firefox discloses the hostname during NTLM
authentication in some circumstances. If a user were tricked in to
opening a specially crafted website with NTLM v1 enabled, an attacker
could exploit this to obtain sensitive information. (CVE-2015-4515)

Mario Heiderich and Frederik Braun discovered that CSP could be bypassed
in reader mode in some circumstances. If a user were tricked in to opening
a specially crafted website, an attacker could potentially exploit this to
conduct cross-site scripting (XSS) attacks. (CVE-2015-4518)

Tyson Smith and David Keeler discovered a use-after-poison and buffer
overflow in NSS. If a user were tricked in to opening a specially crafted
website, an attacker could potentially exploit these to cause a denial of
service via application crash, or execute arbitrary code with the
privileges of the user invoking Firefox. (CVE-2015-7181, CVE-2015-7182)

Ryan Sleevi discovered an integer overflow in NSPR. If a user were tricked
in to opening a specially crafted website, an attacker could potentially
exploit this to cause a denial of service via application crash, or
execute arbitrary code with the privileges of the user invoking Firefox.
(CVE-2015-7183)

Jason Hamilton, Peter Arremann and Sylvain Giroux discovered that panels
created via the Addon SDK with { script: false } could still execute
inline script. If a user installed an addon that relied on this as a
security mechanism, an attacker could potentially exploit this to conduct
cross-site scripting (XSS) attacks, depending on the source of the panel
content. (CVE-2015-7187)

Michal Bentkowski discovered that adding white-space to hostnames that are
IP address can bypass same-origin protections. If a user were tricked in
to opening a specially crafted website, an attacker could potentially
exploit this to conduct cross-site scripting (XSS) attacks.
(CVE-2015-7188)

Looben Yang discovered a buffer overflow during script interactions with
the canvas element in some circumstances. If a user were tricked in to
opening a specially crafted website, an attacker could potentially exploit
this to cause a denial of service via application crash, or execute
arbitrary code with the privileges of the user invoking Firefox.
(CVE-2015-7189)

Shinto K Anto discovered that CORS preflight is bypassed when receiving
non-standard Content-Type headers in some circumstances. If a ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'firefox' package(s) on Ubuntu 12.04, Ubuntu 14.04, Ubuntu 15.04, Ubuntu 15.10.");

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

  if(!isnull(res = isdpkgvuln(pkg:"firefox", ver:"42.0+build2-0ubuntu0.12.04.1", rls:"UBUNTU12.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"firefox", ver:"42.0+build2-0ubuntu0.14.04.1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU15.04") {

  if(!isnull(res = isdpkgvuln(pkg:"firefox", ver:"42.0+build2-0ubuntu0.15.04.1", rls:"UBUNTU15.04"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU15.10") {

  if(!isnull(res = isdpkgvuln(pkg:"firefox", ver:"42.0+build2-0ubuntu0.15.10.1", rls:"UBUNTU15.10"))) {
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
