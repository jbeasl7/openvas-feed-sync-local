# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.62852");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-12-10 05:23:56 +0100 (Wed, 10 Dec 2008)");
  script_cve_id("CVE-2008-2371", "CVE-2008-2829", "CVE-2008-3658", "CVE-2008-3659", "CVE-2008-3660");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("FreeBSD Ports: php5");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following package is affected: php5

CVE-2008-2371
Heap-based buffer overflow in pcre_compile.c in the Perl-Compatible
Regular Expression (PCRE) library 7.7 allows context-dependent
attackers to cause a denial of service (crash) or possibly execute
arbitrary code via a regular expression that begins with an option and
contains multiple branches.
CVE-2008-2829
php_imap.c in PHP 5.2.5, 5.2.6, 4.x, and other versions, uses obsolete
API calls that allow context-dependent attackers to cause a denial of
service (crash) and possibly execute arbitrary code via a long IMAP
request, which triggers an 'rfc822.c legacy routine buffer overflow'
error message.
CVE-2008-3658
Buffer overflow in the imageloadfont function in ext/gd/gd.c in PHP
4.4.x before 4.4.9 and PHP 5.2 before 5.2.6-r6 allows
context-dependent attackers to cause a denial of service (crash) and
possibly execute arbitrary code via a crafted font file.
CVE-2008-3659
Buffer overflow in the memnstr function in PHP 4.4.x before 4.4.9 and
PHP 5.6 through 5.2.6 allows context-dependent attackers to cause a
denial of service (crash) and possibly execute arbitrary code via the
delimiter argument to the explode function.  NOTE: the scope of this
issue is limited since most applications would not use an
attacker-controlled delimiter, but local attacks against safe_mode are
feasible.
CVE-2008-3660
PHP 4.4.x before 4.4.9, and 5.x through 5.2.6, when used as a FastCGI
module, allows remote attackers to cause a denial of service (crash)
via a request with multiple dots preceding the extension, as
demonstrated using foo..php.");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_xref(name:"URL", value:"http://www.php.net/ChangeLog-5.php#5.2.7");
  script_xref(name:"URL", value:"http://www.sektioneins.de/advisories/SE-2008-06.txt");
  script_xref(name:"URL", value:"http://secunia.com/advisories/30916/");
  script_xref(name:"URL", value:"http://secunia.com/advisories/31409/");
  script_xref(name:"URL", value:"http://secunia.com/advisories/32964/");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/27d01223-c457-11dd-a721-0030843d3802.html");

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
if(!isnull(bver) && revcomp(a:bver, b:"5.2.7")<0) {
  txt += 'Package php5 version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}