# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.53766");
  script_cve_id("CVE-2001-0361");
  script_version("2023-07-19T05:05:15+0000");
  script_tag(name:"last_modification", value:"2023-07-19 05:05:15 +0000 (Wed, 19 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-01-17 14:24:38 +0100 (Thu, 17 Jan 2008)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:P/A:N");
  script_name("Debian Security Advisory DSA 086-1 (ssh-nonfree, ssh-socks)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB2\.2");
  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=DSA%20086-1");
  script_tag(name:"insight", value:"We have received reports that the SSH CRC-32 compensation attack
detector vulnerability is being actively exploited. This is the same
integer type error previously corrected for OpenSSH in DSA-027-1.
OpenSSH (the Debian ssh package) was fixed at that time, but
ssh-nonfree and ssh-socks were not.

Though packages in the non-free section of the archive are not
officially supported by the Debian project, we are taking the unusual
step of releasing updated ssh-nonfree/ssh-socks packages for those
users who have not yet migrated to OpenSSH. However, we do recommend
that our users migrate to the regularly supported, DFSG-free ssh
package as soon as possible. ssh 1.2.3-9.3 is the OpenSSH package
available in Debian 2.2r4.

The fixed ssh-nonfree/ssh-socks packages are available in version
1.2.27-6.2 for use with Debian 2.2 (potato) and version 1.2.27-8 for
use with the Debian unstable/testing distribution. Note that the new
ssh-nonfree/ssh-socks packages remove the setuid bit from the ssh
binary, disabling rhosts-rsa authentication. If you need this
functionality, run
chmod u+s /usr/bin/ssh1
after installing the new package.");
  script_tag(name:"summary", value:"The remote host is missing an update to ssh-nonfree, ssh-socks
announced via advisory DSA 086-1.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution", value:"Please install the updated package(s).");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"ssh-askpass-nonfree", ver:"1.2.27-6.2", rls:"DEB2.2")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"ssh-nonfree", ver:"1.2.27-6.2", rls:"DEB2.2")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"ssh-socks", ver:"1.2.27-6.2", rls:"DEB2.2")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}
