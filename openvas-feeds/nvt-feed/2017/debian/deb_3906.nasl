# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703906");
  script_cve_id("CVE-2017-2666", "CVE-2017-2670");
  script_tag(name:"creation_date", value:"2017-07-10 22:00:00 +0000 (Mon, 10 Jul 2017)");
  script_version("2024-02-02T05:06:06+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:06 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-10-02 14:07:35 +0000 (Tue, 02 Oct 2018)");

  script_name("Debian: Security Advisory (DSA-3906-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");

  script_xref(name:"Advisory-ID", value:"DSA-3906-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2017/DSA-3906-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-3906");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'undertow' package(s) announced via the DSA-3906-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Two vulnerabilities have been discovered in Undertow, a web server written in Java, which may lead to denial of service or HTTP request smuggling.

For the stable distribution (stretch), these problems have been fixed in version 1.4.8-1+deb9u1.

For the testing distribution (buster), these problems have been fixed in version 1.4.18-1.

For the unstable distribution (sid), these problems have been fixed in version 1.4.18-1.

We recommend that you upgrade your undertow packages.");

  script_tag(name:"affected", value:"'undertow' package(s) on Debian 9.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libundertow-java", ver:"1.4.8-1+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libundertow-java-doc", ver:"1.4.8-1+deb9u1", rls:"DEB9"))) {
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
