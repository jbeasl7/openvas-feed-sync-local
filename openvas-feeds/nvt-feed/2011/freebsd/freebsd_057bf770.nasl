# SPDX-FileCopyrightText: 2011 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.70257");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2011-09-21 05:47:11 +0200 (Wed, 21 Sep 2011)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2011-2483", "CVE-2011-2202", "CVE-2011-1938", "CVE-2011-1148");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/49241");
  script_name("FreeBSD Ports: php5, php5-sockets");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following packages are affected:

  php5
   php5-sockets

CVE-2011-2483
crypt_blowfish before 1.1, as used in PHP before 5.3.7 on certain
platforms, does not properly handle 8-bit characters, which makes it
easier for context-dependent attackers to determine a cleartext
password by leveraging knowledge of a password hash.

CVE-2011-2202
The rfc1867_post_handler function in main/rfc1867.c in PHP before
5.3.7 does not properly restrict filenames in multipart/form-data POST
requests, which allows remote attackers to conduct absolute path
traversal attacks, and possibly create or overwrite arbitrary files,
via a crafted upload request, related to a 'file path injection
vulnerability.'

CVE-2011-1938
Stack-based buffer overflow in the socket_connect function in
ext/sockets/sockets.c in PHP 5.3.3 through 5.3.6 might allow
context-dependent attackers to execute arbitrary code via a long
pathname for a UNIX socket.

CVE-2011-1148
Use-after-free vulnerability in the substr_replace function in PHP
5.3.6 and earlier allows context-dependent attackers to cause a denial
of service (memory corruption) or possibly have unspecified other
impact by using the same variable for multiple arguments.");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_tag(name:"summary", value:"The remote host is missing an update to the system
  as announced in the referenced advisory.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-bsd.inc");

vuln = FALSE;
txt = "";

bver = portver(pkg:"php5");
if(!isnull(bver) && revcomp(a:bver, b:"5.3.7")<0) {
  txt += 'Package php5 version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"php5-sockets");
if(!isnull(bver) && revcomp(a:bver, b:"5.3.7")<0) {
  txt += 'Package php5-sockets version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}