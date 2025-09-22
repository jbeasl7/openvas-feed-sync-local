# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.53794");
  script_cve_id("CVE-2001-0456");
  script_version("2023-07-19T05:05:15+0000");
  script_tag(name:"last_modification", value:"2023-07-19 05:05:15 +0000 (Wed, 19 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-01-17 14:24:38 +0100 (Thu, 17 Jan 2008)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Debian Security Advisory DSA 032-1 (proftpd)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB2\.2");
  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=DSA%20032-1");
  script_tag(name:"insight", value:"The following problems have been reported for the version of proftpd in
Debian 2.2 (potato):

1. There is a configuration error in the postinst script, when the user
enters 'yes', when asked if anonymous access should be enabled.
The postinst script wrongly leaves the 'run as uid/gid root' configuration
option in /etc/proftpd.conf, and adds a 'run as uid/gid nobody' option that
has no effect.

2. There is a bug that comes up when /var is a symlink, and proftpd is
restarted. When stopping proftpd, the /var symlink is removed. When it's
started again a file named /var is created.

The above problems have been corrected in proftpd-1.2.0pre10-2.0potato1.
We recommend you upgrade your proftpd package immediately.");
  script_tag(name:"summary", value:"The remote host is missing an update to proftpd
announced via advisory DSA 032-1.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution", value:"Please install the updated package(s).");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"proftpd", ver:"1.2.0pre10-2.0potato1", rls:"DEB2.2")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}
