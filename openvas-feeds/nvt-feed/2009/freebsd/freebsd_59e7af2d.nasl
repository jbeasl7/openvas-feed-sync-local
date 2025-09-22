# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.64784");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-09-02 04:58:39 +0200 (Wed, 02 Sep 2009)");
  script_cve_id("CVE-2009-2694");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("FreeBSD Ports: pidgin, libpurple, finch");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following packages are affected:

  pidgin
   libpurple
   finch

CVE-2009-2694
The msn_slplink_process_msg function in
libpurple/protocols/msn/slplink.c in libpurple, as used in Pidgin
(formerly Gaim) before 2.5.9 and Adium 1.3.5 and earlier, allows
remote attackers to execute arbitrary code or cause a denial of
service (memory corruption and application crash) by sending multiple
crafted SLP (aka MSNSLP) messages to trigger an overwrite of an
arbitrary memory location.  NOTE: this issue reportedly exists because
of an incomplete fix for CVE-2009-1376.");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_xref(name:"URL", value:"http://secunia.com/advisories/36384/");
  script_xref(name:"URL", value:"http://www.pidgin.im/news/security/?id=34");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/59e7af2d-8db7-11de-883b-001e3300a30d.html");

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

bver = portver(pkg:"pidgin");
if(!isnull(bver) && revcomp(a:bver, b:"2.5.9")<0) {
  txt += 'Package pidgin version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"libpurple");
if(!isnull(bver) && revcomp(a:bver, b:"2.5.9")<0) {
  txt += 'Package libpurple version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"finch");
if(!isnull(bver) && revcomp(a:bver, b:"2.5.9")<0) {
  txt += 'Package finch version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}