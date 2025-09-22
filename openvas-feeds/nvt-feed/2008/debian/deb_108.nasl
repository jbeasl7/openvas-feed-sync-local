# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.53388");
  script_cve_id("CVE-2002-0247", "CVE-2002-0248");
  script_version("2023-10-06T16:09:51+0000");
  script_tag(name:"last_modification", value:"2023-10-06 16:09:51 +0000 (Fri, 06 Oct 2023)");
  script_tag(name:"creation_date", value:"2008-01-17 22:24:46 +0100 (Thu, 17 Jan 2008)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Debian Security Advisory DSA 108-1 (wmtv)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB2\.2");
  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=DSA%20108-1");
  script_tag(name:"insight", value:"Nicolas Boullis found some security problems in the wmtv package (a
dockable video4linux TV player for windowmaker) which is distributed
in Debian GNU/Linux 2.2.  With the current version of wmtv, the
configuration file is written back as the superuser, and without any
further checks.  A malicious user might use that to damage important
files

This problem has been fixed in version 0.6.5-2potato2 for the stable
distribution by dropping privileges as soon as possible and only
regaining them where required.  In the current testing/unstable
distribution this problem has been fixed in version 0.6.5-9 and above
by not requiring privileges anymore.  Both contain fixes for two
potential buffer overflows as well.");

  script_tag(name:"solution", value:"We recommend that you upgrade your wmtv packages immediately.");
  script_tag(name:"summary", value:"The remote host is missing an update to wmtv
announced via advisory DSA 108-1.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"wmtv", ver:"0.6.5-2potato2", rls:"DEB2.2")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}
