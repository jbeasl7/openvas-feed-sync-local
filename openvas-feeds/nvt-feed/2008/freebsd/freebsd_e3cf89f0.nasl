# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.52540");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-09-04 20:41:11 +0200 (Thu, 04 Sep 2008)");
  script_cve_id("CVE-2004-1315");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("FreeBSD Ports: phpbb");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following package is affected: phpbb

CVE-2004-1315
viewtopic.php in phpBB 2.x before 2.0.11 improperly URL decodes the
highlight parameter when extracting words and phrases to highlight,
which allows remote attackers to execute arbitrary PHP code by
double-encoding the highlight value so that special characters are
inserted into the result, which is then processed by PHP exec, as
exploited by the Santy.A worm.");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_xref(name:"URL", value:"http://www.phpbb.com/support/documents.php?mode=changelog");
  script_xref(name:"URL", value:"http://www.phpbb.com/phpBB/viewtopic.php?f=14&t=240636");
  script_xref(name:"URL", value:"https://marc.info/?l=bugtraq&m=110029415208724");
  script_xref(name:"URL", value:"https://marc.info/?l=bugtraq&m=110079436714518");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/e3cf89f0-53da-11d9-92b7-ceadd4ac2edd.html");

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

bver = portver(pkg:"phpbb");
if(!isnull(bver) && revcomp(a:bver, b:"2.0.11")<0) {
  txt += 'Package phpbb version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}