# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704554");
  script_cve_id("CVE-2019-15587");
  script_tag(name:"creation_date", value:"2019-10-30 03:00:05 +0000 (Wed, 30 Oct 2019)");
  script_version("2024-02-02T05:06:06+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:06 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-24 15:26:37 +0000 (Thu, 24 Oct 2019)");

  script_name("Debian: Security Advisory (DSA-4554-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(10|9)");

  script_xref(name:"Advisory-ID", value:"DSA-4554-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2019/DSA-4554-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-4554");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/ruby-loofah");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'ruby-loofah' package(s) announced via the DSA-4554-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that ruby-loofah, a general library for manipulating and transforming HTML/XML documents and fragments, was susceptible to cross-site scripting.

For the oldstable distribution (stretch), this problem has been fixed in version 2.0.3-2+deb9u3.

For the stable distribution (buster), this problem has been fixed in version 2.2.3-1+deb10u1.

We recommend that you upgrade your ruby-loofah packages.

For the detailed security status of ruby-loofah please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'ruby-loofah' package(s) on Debian 9, Debian 10.");

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

  if(!isnull(res = isdpkgvuln(pkg:"ruby-loofah", ver:"2.2.3-1+deb10u1", rls:"DEB10"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"ruby-loofah", ver:"2.0.3-2+deb9u3", rls:"DEB9"))) {
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
