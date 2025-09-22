# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.840060");
  script_cve_id("CVE-2006-2894", "CVE-2007-1095", "CVE-2007-2292", "CVE-2007-3511", "CVE-2007-5334", "CVE-2007-5337", "CVE-2007-5338", "CVE-2007-5339", "CVE-2007-5340");
  script_tag(name:"creation_date", value:"2009-03-23 09:59:50 +0000 (Mon, 23 Mar 2009)");
  script_version("2024-02-02T05:06:04+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:04 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-536-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(6\.06\ LTS|6\.10|7\.04|7\.10)");

  script_xref(name:"Advisory-ID", value:"USN-536-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-536-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'mozilla-thunderbird, thunderbird' package(s) announced via the USN-536-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Various flaws were discovered in the layout and JavaScript engines. By
tricking a user into opening a malicious web page, an attacker could
execute arbitrary code with the user's privileges. (CVE-2007-5339,
CVE-2007-5340)

Flaws were discovered in the file upload form control. By tricking
a user into opening a malicious web page, an attacker could force
arbitrary files from the user's computer to be uploaded without their
consent. (CVE-2006-2894, CVE-2007-3511)

Michal Zalewski discovered that the onUnload event handlers were
incorrectly able to access information outside the old page content. A
malicious web site could exploit this to modify the contents, or
steal confidential data (such as passwords), of the next loaded web
page. (CVE-2007-1095)

Stefano Di Paola discovered that Thunderbird did not correctly request
Digest Authentications. A malicious web site could exploit this to
inject arbitrary HTTP headers or perform session splitting attacks
against proxies. (CVE-2007-2292)

Eli Friedman discovered that XUL could be used to hide a window's
titlebar. A malicious web site could exploit this to enhance their
attempts at creating phishing web sites. (CVE-2007-5334)

Georgi Guninski discovered that Thunderbird would allow file-system based
web pages to access additional files. By tricking a user into opening
a malicious web page from a gnome-vfs location, an attacker could steal
arbitrary files from the user's computer. (CVE-2007-5337)

It was discovered that the XPCNativeWrappers were not safe in
certain situations. By tricking a user into opening a malicious web
page, an attacker could run arbitrary JavaScript with the user's
privileges. (CVE-2007-5338)

Please note that JavaScript is disabled by default for emails, and it
is not recommended to enable it.");

  script_tag(name:"affected", value:"'mozilla-thunderbird, thunderbird' package(s) on Ubuntu 6.06, Ubuntu 6.10, Ubuntu 7.04, Ubuntu 7.10.");

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

if(release == "UBUNTU6.06 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"mozilla-thunderbird", ver:"1.5.0.13+1.5.0.14b-0ubuntu0.6.06", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU6.10") {

  if(!isnull(res = isdpkgvuln(pkg:"mozilla-thunderbird", ver:"1.5.0.13+1.5.0.14b-0ubuntu0.6.10", rls:"UBUNTU6.10"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU7.04") {

  if(!isnull(res = isdpkgvuln(pkg:"mozilla-thunderbird", ver:"1.5.0.13+1.5.0.14b-0ubuntu0.7.04", rls:"UBUNTU7.04"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU7.10") {

  if(!isnull(res = isdpkgvuln(pkg:"mozilla-thunderbird", ver:"2.0.0.8~pre071022+nobinonly-0ubuntu0.7.10", rls:"UBUNTU7.10"))) {
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
