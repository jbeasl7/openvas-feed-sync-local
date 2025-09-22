# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704587");
  script_cve_id("CVE-2019-15845", "CVE-2019-16201", "CVE-2019-16254", "CVE-2019-16255");
  script_tag(name:"creation_date", value:"2019-12-18 03:00:57 +0000 (Wed, 18 Dec 2019)");
  script_version("2024-02-02T05:06:06+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:06 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-07-17 20:10:13 +0000 (Fri, 17 Jul 2020)");

  script_name("Debian: Security Advisory (DSA-4587-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");

  script_xref(name:"Advisory-ID", value:"DSA-4587-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2019/DSA-4587-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-4587");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/ruby2.3");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'ruby2.3' package(s) announced via the DSA-4587-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in the interpreter for the Ruby language, which could result in unauthorized access by bypassing intended path matchings, denial of service, or the execution of arbitrary code.

For the oldstable distribution (stretch), these problems have been fixed in version 2.3.3-1+deb9u7.

We recommend that you upgrade your ruby2.3 packages.

For the detailed security status of ruby2.3 please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'ruby2.3' package(s) on Debian 9.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libruby2.3", ver:"2.3.3-1+deb9u7", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ruby2.3", ver:"2.3.3-1+deb9u7", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ruby2.3-dev", ver:"2.3.3-1+deb9u7", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ruby2.3-doc", ver:"2.3.3-1+deb9u7", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ruby2.3-tcltk", ver:"2.3.3-1+deb9u7", rls:"DEB9"))) {
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
