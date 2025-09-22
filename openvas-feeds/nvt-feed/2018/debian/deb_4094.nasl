# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704094");
  script_cve_id("CVE-2017-1000480");
  script_tag(name:"creation_date", value:"2018-01-21 23:00:00 +0000 (Sun, 21 Jan 2018)");
  script_version("2024-02-02T05:06:06+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:06 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-01-18 23:19:55 +0000 (Thu, 18 Jan 2018)");

  script_name("Debian: Security Advisory (DSA-4094-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(8|9)");

  script_xref(name:"Advisory-ID", value:"DSA-4094-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2018/DSA-4094-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-4094");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/smarty3");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'smarty3' package(s) announced via the DSA-4094-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that Smarty, a PHP template engine, was vulnerable to code-injection attacks. An attacker was able to craft a filename in comments that could lead to arbitrary code execution on the host running Smarty.

For the oldstable distribution (jessie), this problem has been fixed in version 3.1.21-1+deb8u1.

For the stable distribution (stretch), this problem has been fixed in version 3.1.31+20161214.1.c7d42e4+selfpack1-2+deb9u1.

We recommend that you upgrade your smarty3 packages.

For the detailed security status of smarty3 please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'smarty3' package(s) on Debian 8, Debian 9.");

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

  if(!isnull(res = isdpkgvuln(pkg:"smarty3", ver:"3.1.21-1+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "DEB9") {

  if(!isnull(res = isdpkgvuln(pkg:"smarty3", ver:"3.1.31+20161214.1.c7d42e4+selfpack1-2+deb9u1", rls:"DEB9"))) {
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
