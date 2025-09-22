# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.64266");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-06-23 15:49:15 +0200 (Tue, 23 Jun 2009)");
  script_cve_id("CVE-2009-1373", "CVE-2009-1374", "CVE-2009-1375", "CVE-2009-1376");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
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

CVE-2009-1373
Buffer overflow in the XMPP SOCKS5 bytestream server in Pidgin
(formerly Gaim) before 2.5.6 allows remote authenticated users to
execute arbitrary code via vectors involving an outbound XMPP file
transfer.  NOTE: some of these details are obtained from third party
information.
CVE-2009-1374
Buffer overflow in the decrypt_out function in Pidgin (formerly Gaim)
before 2.5.6 allows remote attackers to cause a denial of service
(application crash) via a QQ packet.
CVE-2009-1375
The PurpleCircBuffer implementation in Pidgin (formerly Gaim) before
2.5.6 does not properly maintain a certain buffer, which allows remote
attackers to cause a denial of service (memory corruption and
application crash) via vectors involving the (1) XMPP or (2) Sametime
protocol.
CVE-2009-1376
Multiple integer overflows in the msn_slplink_process_msg functions in
the MSN protocol handler in (1) libpurple/protocols/msn/slplink.c and
(2) libpurple/protocols/msnp9/slplink.c in Pidgin (formerly Gaim)
before 2.5.6 on 32-bit platforms allow remote attackers to execute
arbitrary code via a malformed SLP message with a crafted offset
value, leading to buffer overflows.  NOTE: this issue exists because
of an incomplete fix for CVE-2008-2927.");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_xref(name:"URL", value:"http://secunia.com/advisories/35194/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/35067");
  script_xref(name:"URL", value:"http://www.pidgin.im/news/security/?id=29");
  script_xref(name:"URL", value:"http://www.pidgin.im/news/security/?id=30");
  script_xref(name:"URL", value:"http://www.pidgin.im/news/security/?id=32");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/b1ca65e6-5aaf-11de-bc9b-0030843d3802.html");

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
if(!isnull(bver) && revcomp(a:bver, b:"2.5.6")<0) {
  txt += 'Package pidgin version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"libpurple");
if(!isnull(bver) && revcomp(a:bver, b:"2.5.6")<0) {
  txt += 'Package libpurple version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"finch");
if(!isnull(bver) && revcomp(a:bver, b:"2.5.6")<0) {
  txt += 'Package finch version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}