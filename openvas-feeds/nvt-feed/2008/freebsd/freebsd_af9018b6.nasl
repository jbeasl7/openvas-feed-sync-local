# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.56314");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-09-04 20:41:11 +0200 (Thu, 04 Sep 2008)");
  script_cve_id("CVE-2006-0377", "CVE-2006-0195", "CVE-2006-0188");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_name("FreeBSD Ports: squirrelmail");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_xref(name:"URL", value:"https://www.vuxml.org/freebsd/af9018b6-a4f5-11da-bb41-0011433a9404.html");
  script_tag(name:"insight", value:"The following package is affected: squirrelmail

CVE-2006-0377
CRLF injection vulnerability in SquirrelMail 1.4.0 to 1.4.5 allows
remote attackers to inject arbitrary IMAP commands via newline
characters in the mailbox parameter of the sqimap_mailbox_select
command, aka 'IMAP injection.'

CVE-2006-0195
Interpretation conflict in the MagicHTML filter in SquirrelMail 1.4.0
to 1.4.5 allows remote attackers to conduct cross-site scripting (XSS)
attacks via style sheet specifiers with invalid (1) '/*' and '*/'
comments, or (2) a newline in a 'url' specifier, which is processed by
certain web browsers including Internet Explorer.

CVE-2006-0188
webmail.php in SquirrelMail 1.4.0 to 1.4.5 allows remote attackers to
inject arbitrary web pages into the right frame via a URL in the
right_frame parameter.  NOTE: this has been called a cross-site
scripting (XSS) issue, but it is different than what is normally
identified as XSS.");

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

bver = portver(pkg:"squirrelmail");
if(!isnull(bver) && revcomp(a:bver, b:"1.4.6")<0) {
  txt += 'Package squirrelmail version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}
