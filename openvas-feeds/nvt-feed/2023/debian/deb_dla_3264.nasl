# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.893264");
  script_cve_id("CVE-2022-45442");
  script_tag(name:"creation_date", value:"2023-01-11 02:00:23 +0000 (Wed, 11 Jan 2023)");
  script_version("2024-02-02T05:06:10+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:10 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-12-01 23:11:57 +0000 (Thu, 01 Dec 2022)");

  script_name("Debian: Security Advisory (DLA-3264-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB10");

  script_xref(name:"Advisory-ID", value:"DLA-3264-1");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2023/DLA-3264-1");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'ruby-sinatra' package(s) announced via the DLA-3264-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that there was a potential reflected file download (RFD) vulnerability in ruby-sinatra, a Ruby library for writing HTTP applications. A Content-Disposition HTTP header was being incorrectly derived from a potentially user-supplied filename.

CVE-2022-45442

Sinatra is a domain-specific language for creating web applications in Ruby. An issue was discovered in Sinatra 2.0 before 2.2.3 and 3.0 before 3.0.4. An application is vulnerable to a reflected file download (RFD) attack that sets the Content-Disposition header of a response when the filename is derived from user-supplied input. Version 2.2.3 and 3.0.4 contain patches for this issue.

For Debian 10 Buster, this problem has been fixed in version 2.0.5-4+deb10u2.

We recommend that you upgrade your ruby-sinatra packages.

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'ruby-sinatra' package(s) on Debian 10.");

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

if(release == "DEB10") {

  if(!isnull(res = isdpkgvuln(pkg:"ruby-rack-protection", ver:"2.0.5-4+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ruby-sinatra", ver:"2.0.5-4+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ruby-sinatra-contrib", ver:"2.0.5-4+deb10u2", rls:"DEB10"))) {
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
