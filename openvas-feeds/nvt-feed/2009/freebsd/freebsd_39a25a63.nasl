# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.66610");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-12-30 21:58:43 +0100 (Wed, 30 Dec 2009)");
  script_cve_id("CVE-2009-3557", "CVE-2009-3558", "CVE-2009-4017", "CVE-2009-4142", "CVE-2009-4143");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("FreeBSD Ports: php5");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following package is affected: php5

CVE-2009-3557
The tempnam function in ext/standard/file.c in PHP before 5.2.12 and
5.3.x before 5.3.1 allows context-dependent attackers to bypass
safe_mode restrictions, and create files in group-writable or
world-writable directories, via the dir and prefix arguments.

CVE-2009-3558
The posix_mkfifo function in ext/posix/posix.c in PHP before 5.2.12
and 5.3.x before 5.3.1 allows context-dependent attackers to bypass
open_basedir restrictions, and create FIFO files, via the pathname and
mode arguments, as demonstrated by creating a .htaccess file.

CVE-2009-4017
PHP before 5.2.12 and 5.3.x before 5.3.1 does not restrict the number
of temporary files created when handling a multipart/form-data POST
request, which allows remote attackers to cause a denial of service
(resource exhaustion), and makes it easier for remote attackers to
exploit local file inclusion vulnerabilities, via multiple requests,
related to lack of support for the max_file_uploads directive.

CVE-2009-4142
The htmlspecialchars function in PHP before 5.2.12 does not properly
handle (1) overlong UTF-8 sequences, (2) invalid Shift_JIS sequences,
and (3) invalid EUC-JP sequences, which allows remote attackers to
conduct cross-site scripting (XSS) attacks by placing a crafted byte
sequence before a special character.

CVE-2009-4143
PHP before 5.2.12 does not properly handle session data, which has
unspecified impact and attack vectors related to (1) interrupt
corruption of the SESSION superglobal array and (2) the
session.save_path directive.");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_xref(name:"URL", value:"http://www.php.net/releases/5_2_12.php");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/39a25a63-eb5c-11de-b650-00215c6a37bb.html");

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
if(!isnull(bver) && revcomp(a:bver, b:"5.2.12")<0) {
  txt += 'Package php5 version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}