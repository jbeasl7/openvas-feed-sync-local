# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.52430");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-09-04 20:41:11 +0200 (Thu, 04 Sep 2008)");
  script_cve_id("CVE-2004-0597", "CVE-2004-0598", "CVE-2004-0599");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("FreeBSD Ports: ImageMagick, ImageMagick-nox11");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following packages are affected:

  ImageMagick
   ImageMagick-nox11

CVE-2004-0597
Multiple buffer overflows in libpng 1.2.5 and earlier, as used in
multiple products, allow remote attackers to execute arbitrary code
via malformed PNG images in which (1) the png_handle_tRNS function
does not properly validate the length of transparency chunk (tRNS)
data, or the (2) png_handle_sBIT or (3) png_handle_hIST functions do
not perform sufficient bounds checking.

CVE-2004-0598
The png_handle_iCCP function in libpng 1.2.5 and earlier allows
remote attackers to cause a denial of service (application crash)
via a certain PNG image that triggers a null dereference.

CVE-2004-0599
Multiple integer overflows in the (1) png_read_png in pngread.c
or (2) png_handle_sPLT functions in pngrutil.c or (3) progressive
display image reading capability in libpng 1.2.5 and earlier allow
remote attackers to cause a denial of service (application crash)
via a malformed PNG image.");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_xref(name:"URL", value:"http://studio.imagemagick.org/pipermail/magick-users/2004-August/013218.html");
  script_xref(name:"URL", value:"http://freshmeat.net/releases/169228");
  script_xref(name:"URL", value:"http://secunia.com/advisories/12236");
  script_xref(name:"URL", value:"http://www.freebsd.org/ports/portaudit/f9e3e60b-e650-11d8-9b0a-000347a4fa7d.html");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/a713c0f9-ec54-11d8-9440-000347a4fa7d.html");

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

bver = portver(pkg:"ImageMagick");
if(!isnull(bver) && revcomp(a:bver, b:"6.0.4.2")<0) {
  txt += 'Package ImageMagick version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"ImageMagick-nox11");
if(!isnull(bver) && revcomp(a:bver, b:"6.0.4.2")<0) {
  txt += 'Package ImageMagick-nox11 version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}