# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.53741");
  script_version("2023-07-19T05:05:15+0000");
  script_tag(name:"last_modification", value:"2023-07-19 05:05:15 +0000 (Wed, 19 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-01-17 22:28:10 +0100 (Thu, 17 Jan 2008)");
  script_cve_id("CVE-2002-1403");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Debian Security Advisory DSA 219-1 (dhcpcd)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB2\.2");
  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=DSA%20219-1");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/6200");
  script_tag(name:"insight", value:"Simon Kelly discovered a vulnerability in dhcpcd, an RFC2131 and
RFC1541 compliant DHCP client daemon, that runs with root privileges
on client machines.  A malicious administrator of the regular or an
untrusted DHCP server may execute any command with root privileges on
the DHCP client machine by sending the command enclosed in shell
metacharacters in one of the options provided by the DHCP server.

This problem has been fixed in version 1.3.17pl2-8.1 for the old
stable distribution (potato) and in version 1.3.22pl2-2 for the
testing (sarge) and unstable (sid) distributions.  The current stable
distribution (woody) does not contain a dhcpcd package.");

  script_tag(name:"solution", value:"We recommend that you upgrade your dhcpcd package (on the client");
  script_tag(name:"summary", value:"The remote host is missing an update to dhcpcd
announced via advisory DSA 219-1.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"dhcpcd", ver:"1.3.17pl2-8.1", rls:"DEB2.2")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}
