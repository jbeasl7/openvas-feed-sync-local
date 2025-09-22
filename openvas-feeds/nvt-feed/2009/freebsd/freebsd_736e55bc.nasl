# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.63967");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-05-11 20:24:31 +0200 (Mon, 11 May 2009)");
  script_cve_id("CVE-2009-0163", "CVE-2009-0164", "CVE-2009-0146", "CVE-2009-0147", "CVE-2009-0166");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_name("FreeBSD Ports: cups-base");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following package is affected: cups-base

CVE-2009-0163
Integer overflow in the TIFF image decoding routines in CUPS 1.3.9 and
earlier allows remote attackers to cause a denial of service (daemon
crash) and possibly execute arbitrary code via a crafted TIFF image,
which is not properly handled by the (1) _cupsImageReadTIFF function
in the imagetops filter and (2) imagetoraster filter, leading to a
heap-based buffer overflow.

CVE-2009-0164
The web interface for CUPS before 1.3.10 does not validate the HTTP
Host header in a client request, which makes it easier for remote
attackers to conduct DNS rebinding attacks.

CVE-2009-0146
Multiple buffer overflows in the JBIG2 decoder in Xpdf 3.02pl2 and
earlier, CUPS 1.3.9 and earlier, and other products allow remote
attackers to cause a denial of service (crash) via a crafted PDF file,
related to (1) JBIG2SymbolDict::setBitmap and (2)
JBIG2Stream::readSymbolDictSeg.

CVE-2009-0147
Multiple integer overflows in the JBIG2 decoder in Xpdf 3.02pl2 and
earlier, CUPS 1.3.9 and earlier, and other products allow remote
attackers to cause a denial of service (crash) via a crafted PDF file,
related to (1) JBIG2Stream::readSymbolDictSeg, (2)
JBIG2Stream::readSymbolDictSeg, and (3)
JBIG2Stream::readGenericBitmap.

CVE-2009-0166
The JBIG2 decoder in Xpdf 3.02pl2 and earlier, CUPS 1.3.9 and earlier,
and other products allows remote attackers to cause a denial of
service (crash) via a crafted PDF file that triggers a free of
uninitialized memory.");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_xref(name:"URL", value:"http://www.cups.org/articles.php?L582");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/34568");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/34571");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/34665");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/736e55bc-39bb-11de-a493-001b77d09812.html");

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

bver = portver(pkg:"cups-base");
if(!isnull(bver) && revcomp(a:bver, b:"1.3.10")<0) {
  txt += 'Package cups-base version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}