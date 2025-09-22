# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.61219");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-09-04 20:41:11 +0200 (Thu, 04 Sep 2008)");
  script_cve_id("CVE-2008-1806", "CVE-2008-1807", "CVE-2008-1808");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("FreeBSD Ports: freetype2");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following package is affected: freetype2

CVE-2008-1806
Integer overflow in FreeType2 before 2.3.6 allows context-dependent
attackers to execute arbitrary code via a crafted set of 16-bit length
values within the Private dictionary table in a Printer Font Binary
(PFB) file, which triggers a heap-based buffer overflow.

CVE-2008-1807
FreeType2 before 2.3.6 allow context-dependent attackers to execute
arbitrary code via an invalid 'number of axes' field in a Printer Font
Binary (PFB) file, which triggers a free of arbitrary memory
locations, leading to memory corruption.

CVE-2008-1808
Multiple off-by-one errors in FreeType2 before 2.3.6 allow
context-dependent attackers to execute arbitrary code via (1) a
crafted table in a Printer Font Binary (PFB) file or (2) a crafted SHC
instruction in a TrueType Font (TTF) file, which triggers a heap-based
buffer overflow.");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_xref(name:"URL", value:"http://secunia.com/advisories/30600");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/29637");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/29639");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/29640");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/29641");
  script_xref(name:"URL", value:"http://sourceforge.net/project/shownotes.php?release_id=605780");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/4fb43b2f-46a9-11dd-9d38-00163e000016.html");

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

bver = portver(pkg:"freetype2");
if(!isnull(bver) && revcomp(a:bver, b:"2.3.6")<0) {
  txt += 'Package freetype2 version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}