# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.54203");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-09-04 20:41:11 +0200 (Thu, 04 Sep 2008)");
  script_cve_id("CVE-2005-0258", "CVE-2005-0259");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_name("FreeBSD Ports: phpbb");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following package is affected: phpbb

CVE-2005-0258
Directory traversal vulnerability in (1) usercp_register.php and (2)
usercp_avatar.php for phpBB 2.0.11, and possibly other versions, with
gallery avatars enabled, allows remote attackers to delete (unlink)
arbitrary files via '/../' sequences in the avatarselect parameter.

CVE-2005-0259
phpBB 2.0.11, and possibly other versions, with remote avatars and
avatar uploading enabled, allows local users to read arbitrary files
by providing both a local and remote location for an avatar, then
modifying the 'Upload Avatar from a URL:' field to reference the
target file.");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_xref(name:"URL", value:"http://security.gentoo.org/glsa/glsa-200503-02.xml");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/12618");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/12621");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/12623");
  script_xref(name:"URL", value:"http://www.idefense.com/application/poi/display?id=205&type=vulnerabilities");
  script_xref(name:"URL", value:"http://www.idefense.com/application/poi/display?id=204&type=vulnerabilities");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/326c517a-d029-11d9-9aed-000e0c2e438a.html");

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
if(!isnull(bver) && revcomp(a:bver, b:"2.0.12")<0) {
  txt += 'Package phpbb version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}