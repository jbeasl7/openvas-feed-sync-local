# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.891390");
  script_cve_id("CVE-2018-1122", "CVE-2018-1123", "CVE-2018-1124", "CVE-2018-1125", "CVE-2018-1126");
  script_tag(name:"creation_date", value:"2018-06-03 22:00:00 +0000 (Sun, 03 Jun 2018)");
  script_version("2024-02-02T05:06:06+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:06 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-06-22 13:51:14 +0000 (Fri, 22 Jun 2018)");

  script_name("Debian: Security Advisory (DLA-1390-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB7");

  script_xref(name:"Advisory-ID", value:"DLA-1390-1");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2018/DLA-1390-1");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'procps' package(s) announced via the DLA-1390-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The Qualys Research Labs discovered multiple vulnerabilities in procps, a set of command line and full screen utilities for browsing procfs. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2018-1122

top read its configuration from the current working directory if no $HOME was configured. If top were started from a directory writable by the attacker (such as /tmp) this could result in local privilege escalation.

CVE-2018-1123

Denial of service against the ps invocation of another user.

CVE-2018-1124

An integer overflow in the file2strvec() function of libprocps could result in local privilege escalation.

CVE-2018-1125

A stack-based buffer overflow in pgrep could result in denial of service for a user using pgrep for inspecting a specially crafted process.

CVE-2018-1126

Incorrect integer size parameters used in wrappers for standard C allocators could cause integer truncation and lead to integer overflow issues.

For Debian 7 Wheezy, these problems have been fixed in version 1:3.3.3.3+deb7u1.

We recommend that you upgrade your procps packages.

The Debian LTS team would like to thank Abhijith PA for preparing this update.

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'procps' package(s) on Debian 7.");

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

if(release == "DEB7") {

  if(!isnull(res = isdpkgvuln(pkg:"libprocps0", ver:"1:3.3.3-3+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libprocps0-dev", ver:"1:3.3.3-3+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"procps", ver:"1:3.3.3-3+deb7u1", rls:"DEB7"))) {
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
