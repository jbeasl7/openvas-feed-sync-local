# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.53567");
  script_cve_id("CVE-2001-0735");
  script_version("2023-07-19T05:05:15+0000");
  script_tag(name:"last_modification", value:"2023-07-19 05:05:15 +0000 (Wed, 19 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-01-17 14:24:38 +0100 (Thu, 17 Jan 2008)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Debian Security Advisory DSA 066-1 (cfingerd)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB2\.2");
  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=DSA%20066-1");
  script_tag(name:"insight", value:"Steven van Acker reported on bugtraq that the version of cfingerd (a
configurable finger daemon) as distributed in Debian GNU/Linux 2.2
suffers from two problems:

1. The code that reads configuration files (files in which $ commands are
expanded) copied its input to a buffer without checking for a buffer
overflow. When the ALLOW_LINE_PARSING feature is enabled that code
is used for reading users files as well, so local users could exploit
this.

2. There also was a printf call in the same routine that did not protect
against printf format attacks.

Since ALLOW_LINE_PARSING is enabled in the default /etc/cfingerd.conf
local users could use this to gain root access.

This has been fixed in version 1.4.1-1.2, and we recommend that you upgrade");
  script_tag(name:"summary", value:"The remote host is missing an update to cfingerd
announced via advisory DSA 066-1.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution", value:"Please install the updated package(s).");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"cfingerd", ver:"1.4.1-1.2", rls:"DEB2.2")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}
