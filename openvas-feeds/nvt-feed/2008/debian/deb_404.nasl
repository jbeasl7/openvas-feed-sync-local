# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.53383");
  script_version("2023-07-19T05:05:15+0000");
  script_tag(name:"last_modification", value:"2023-07-19 05:05:15 +0000 (Wed, 19 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-01-17 22:41:51 +0100 (Thu, 17 Jan 2008)");
  script_cve_id("CVE-2003-0962");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Debian Security Advisory DSA 404-1 (rsync)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB3\.0");
  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=DSA%20404-1");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/9153");
  script_tag(name:"insight", value:"The rsync team has received evidence that a vulnerability in all
versions of rsync prior to 2.5.7, a fast remote file copy program, was
recently used in combination with a Linux kernel vulnerability to
compromise the security of a public rsync server.

While this heap overflow vulnerability could not be used by itself to
obtain root access on an rsync server, it could be used in combination
with the recently announced do_brk() vulnerability in the Linux kernel
to produce a full remote compromise.

Please note that this vulnerability only affects the use of rsync as
an rsync server.  To see if you are running a rsync server you
should use the command netstat -a -n to see if you are listening on
TCP port 873.  If you are not listening on TCP port 873 then you are
not running an rsync server.

For the stable distribution (woody) this problem has been fixed in
version 2.5.5-0.2.

For the unstable distribution (sid) this problem has been fixed in
version 2.5.6-1.1.");

  script_tag(name:"solution", value:"We recommend that you upgrade your rsync package immediately if you");
  script_tag(name:"summary", value:"The remote host is missing an update to rsync
announced via advisory DSA 404-1.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"rsync", ver:"2.5.5-0.2", rls:"DEB3.0")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}
