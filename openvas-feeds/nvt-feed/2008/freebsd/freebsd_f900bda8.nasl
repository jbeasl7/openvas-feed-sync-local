# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.57026");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-09-04 20:41:11 +0200 (Thu, 04 Sep 2008)");
  script_cve_id("CVE-2006-3082");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("FreeBSD Ports: gnupg");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following package is affected: gnupg

CVE-2006-3082
parse-packet.c in GnuPG (gpg) 1.4.3 and 1.9.20, and earlier versions,
allows remote attackers to cause a denial of service (gpg crash) and
possibly overwrite memory via a message packet with a large length,
which could lead to an integer overflow, as demonstrated using the

  - -no-armor option.");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_xref(name:"URL", value:"http://cvs.gnupg.org/cgi-bin/viewcvs.cgi/trunk/g10/parse-packet.c?rev=4157&r1=4141&r2=4157");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/18554");
  script_xref(name:"URL", value:"https://marc.info/?l=gnupg-users&m=115124706210430");
  script_xref(name:"URL", value:"https://marc.info/?l=full-disclosure&m=114907659313360");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/f900bda8-0472-11db-bbf7-000c6ec775d9.html");

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

bver = portver(pkg:"gnupg");
if(!isnull(bver) && revcomp(a:bver, b:"1.4.4")<0) {
  txt += 'Package gnupg version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}