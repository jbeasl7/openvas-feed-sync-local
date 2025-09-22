# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.891796");
  script_cve_id("CVE-2018-1000074", "CVE-2018-1000075", "CVE-2018-1000076", "CVE-2018-1000077", "CVE-2018-1000078", "CVE-2019-8321", "CVE-2019-8322", "CVE-2019-8323", "CVE-2019-8324", "CVE-2019-8325");
  script_tag(name:"creation_date", value:"2019-05-21 02:00:23 +0000 (Tue, 21 May 2019)");
  script_version("2024-02-02T05:06:07+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:07 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-04-05 21:30:37 +0000 (Thu, 05 Apr 2018)");

  script_name("Debian: Security Advisory (DLA-1796-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8");

  script_xref(name:"Advisory-ID", value:"DLA-1796-1");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2019/DLA-1796-1");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'jruby' package(s) announced via the DLA-1796-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple vulnerabilities have been discovered in jruby, Java implementation of the Ruby programming language.

CVE-2018-1000074

Deserialization of Untrusted Data vulnerability in owner command that can result in code execution. This attack appear to be exploitable via victim must run the `gem owner` command on a gem with a specially crafted YAML file

CVE-2018-1000075

an infinite loop caused by negative size vulnerability in ruby gem package tar header that can result in a negative size could cause an infinite loop

CVE-2018-1000076

Improper Verification of Cryptographic Signature vulnerability in package.rb that can result in a mis-signed gem could be installed, as the tarball would contain multiple gem signatures.

CVE-2018-1000077

Improper Input Validation vulnerability in ruby gems specification homepage attribute that can result in a malicious gem could set an invalid homepage URL

CVE-2018-1000078

Cross Site Scripting (XSS) vulnerability in gem server display of homepage attribute that can result in XSS. This attack appear to be exploitable via the victim must browse to a malicious gem on a vulnerable gem server

CVE-2019-8321

Gem::UserInteraction#verbose calls say without escaping, escape sequence injection is possible

CVE-2019-8322

The gem owner command outputs the contents of the API response directly to stdout. Therefore, if the response is crafted, escape sequence injection may occur

CVE-2019-8323

Gem::GemcutterUtilities#with_response may output the API response to stdout as it is. Therefore, if the API side modifies the response, escape sequence injection may occur.

CVE-2019-8324

A crafted gem with a multi-line name is not handled correctly. Therefore, an attacker could inject arbitrary code to the stub line of gemspec

CVE-2019-8325

Gem::CommandManager#run calls alert_error without escaping, escape sequence injection is possible. (There are many ways to cause an error.)

For Debian 8 Jessie, these problems have been fixed in version 1.5.6-9+deb8u1.

We recommend that you upgrade your jruby packages.

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'jruby' package(s) on Debian 8.");

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

if(release == "DEB8") {

  if(!isnull(res = isdpkgvuln(pkg:"jruby", ver:"1.5.6-9+deb8u1", rls:"DEB8"))) {
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
