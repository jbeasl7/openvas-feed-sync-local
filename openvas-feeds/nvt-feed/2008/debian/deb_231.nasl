# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.53309");
  script_version("2024-06-26T05:05:39+0000");
  script_tag(name:"last_modification", value:"2024-06-26 05:05:39 +0000 (Wed, 26 Jun 2024)");
  script_tag(name:"creation_date", value:"2008-01-17 22:28:10 +0100 (Thu, 17 Jan 2008)");
  script_cve_id("CVE-2003-0026");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Debian Security Advisory DSA 231-1 (dhcp3)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB3\.0");
  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=DSA%20231-1");
  script_tag(name:"insight", value:"The Internet Software Consortium discovered several vulnerabilities
during an audit of the ISC DHCP Daemon.  The vulnerabilities exist in
error handling routines within the minires library and may be
exploitable as stack overflows.  This could allow a remote attacker to
execute arbitrary code under the user id the dhcpd runs under, usually
root.  Other DHCP servers than dhcp3 doesn't seem to be affected.

For the stable distribution (woody) this problem has been
fixed in version 3.0+3.0.1rc9-2.1.

The old stable distribution (potato) does not contain dhcp3 packages.

For the unstable distribution (sid) this problem has been fixed in
version 3.0+3.0.1rc11-1.");

  script_tag(name:"solution", value:"We recommend that you upgrade your dhcp3-server package.");
  script_tag(name:"summary", value:"The remote host is missing an update to dhcp3
announced via advisory DSA 231-1.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"dhcp3-client", ver:"3.0+3.0.1rc9-2.1", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"dhcp3-common", ver:"3.0+3.0.1rc9-2.1", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"dhcp3-dev", ver:"3.0+3.0.1rc9-2.1", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"dhcp3-relay", ver:"3.0+3.0.1rc9-2.1", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"dhcp3-server", ver:"3.0+3.0.1rc9-2.1", rls:"DEB3.0")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}
