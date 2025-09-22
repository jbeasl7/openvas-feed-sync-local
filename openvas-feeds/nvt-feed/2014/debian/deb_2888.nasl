# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.702888");
  script_cve_id("CVE-2013-4389", "CVE-2013-4491", "CVE-2013-6414", "CVE-2013-6415", "CVE-2013-6417");
  script_tag(name:"creation_date", value:"2014-03-26 23:00:00 +0000 (Wed, 26 Mar 2014)");
  script_version("2024-02-02T05:06:04+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:04 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");

  script_name("Debian: Security Advisory (DSA-2888-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB7");

  script_xref(name:"Advisory-ID", value:"DSA-2888-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2014/DSA-2888-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-2888");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'ruby-actionpack-3.2' package(s) announced via the DSA-2888-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Toby Hsieh, Peter McLarnan, Ankit Gupta, Sudhir Rao and Kevin Reintjes discovered multiple cross-site scripting and denial of service vulnerabilities in Ruby Actionpack.

For the stable distribution (wheezy), these problems have been fixed in version 3.2.6-6+deb7u1.

For the unstable distribution (sid), this problem has been fixed in version 3.2.16-3+0 of the rails-3.2 source package.

We recommend that you upgrade your ruby-actionpack-3.2 packages.");

  script_tag(name:"affected", value:"'ruby-actionpack-3.2' package(s) on Debian 7.");

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

  if(!isnull(res = isdpkgvuln(pkg:"ruby-actionpack-3.2", ver:"3.2.6-6+deb7u1", rls:"DEB7"))) {
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
