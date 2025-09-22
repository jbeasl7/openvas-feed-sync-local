# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.63702");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-03-31 19:20:21 +0200 (Tue, 31 Mar 2009)");
  script_cve_id("CVE-2009-0135", "CVE-2009-0136");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("FreeBSD Ports: amarok");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following package is affected: amarok

CVE-2009-0135
Multiple integer overflows in the Audible::Tag::readTag function in
metadata/audible/audibletag.cpp in Amarok 1.4.10 through 2.0.1 allow
remote attackers to execute arbitrary code via an Audible Audio (.aa)
file with a large (1) nlen or (2) vlen Tag value, each of which
triggers a heap-based buffer overflow.

CVE-2009-0136
Multiple array index errors in the Audible::Tag::readTag function in
metadata/audible/audibletag.cpp in Amarok 1.4.10 through 2.0.1 allow
remote attackers to cause a denial of service (application crash) or
execute arbitrary code via an Audible Audio (.aa) file with a crafted
(1) nlen or (2) vlen Tag value, each of which can lead to an invalid
pointer dereference, or the writing of a 0x00 byte to an arbitrary
memory location, after an allocation failure.");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_xref(name:"URL", value:"http://www.debian.org/security/2009/dsa-1706");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/33210");
  script_xref(name:"URL", value:"http://secunia.com/advisories/33505");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/6bb6188c-17b2-11de-ae4d-0030843d3802.html");

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

bver = portver(pkg:"amarok");
if(!isnull(bver) && revcomp(a:bver, b:"1.4.10_3")<0) {
  txt += 'Package amarok version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}