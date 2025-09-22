# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.892330");
  script_cve_id("CVE-2017-17742", "CVE-2019-16201", "CVE-2019-16254", "CVE-2019-16255", "CVE-2019-8320", "CVE-2019-8321", "CVE-2019-8322", "CVE-2019-8323", "CVE-2019-8324", "CVE-2019-8325");
  script_tag(name:"creation_date", value:"2020-08-17 13:22:39 +0000 (Mon, 17 Aug 2020)");
  script_version("2024-02-02T05:06:07+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:07 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"8.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-06-18 18:30:27 +0000 (Tue, 18 Jun 2019)");

  script_name("Debian: Security Advisory (DLA-2330-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");

  script_xref(name:"Advisory-ID", value:"DLA-2330-1");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2020/DLA-2330-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/jruby");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'jruby' package(s) announced via the DLA-2330-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Brief introduction

CVE-2017-17742

Response Splitting attack in the HTTP server of WEBrick.

CVE-2019-8320

Delete directory using symlink when decompressing tar.

CVE-2019-8321

Escape sequence injection vulnerability in verbose.

CVE-2019-8322

Escape sequence injection vulnerability in gem owner.

CVE-2019-8323

Escape sequence injection vulnerability in API response handling.

CVE-2019-8324

Installing a malicious gem may lead to arbitrary code execution.

CVE-2019-8325

Escape sequence injection vulnerability in errors.

CVE-2019-16201

Regular Expression Denial of Service vulnerability of WEBrick's Digest access authentication.

CVE-2019-16254

HTTP Response Splitting attack in the HTTP server of WEBrick.

CVE-2019-16255

Code injection vulnerability.

For Debian 9 stretch, these problems have been fixed in version 1.7.26-1+deb9u2.

We recommend that you upgrade your jruby packages.

For the detailed security status of jruby please refer to its security tracker page at: [link moved to references]

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'jruby' package(s) on Debian 9.");

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

if(release == "DEB9") {

  if(!isnull(res = isdpkgvuln(pkg:"jruby", ver:"1.7.26-1+deb9u2", rls:"DEB9"))) {
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
