# SPDX-FileCopyrightText: 2010 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.67657");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2010-07-06 02:35:12 +0200 (Tue, 06 Jul 2010)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2010-1411");
  script_name("FreeBSD Ports: tiff");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following packages are affected:

  tiff
   linux-tiff

CVE-2010-1411
Multiple integer overflows in the Fax3SetupState function in
tif_fax3.c in the FAX3 decoder in LibTIFF before 3.9.3, as used in
ImageIO in Apple Mac OS X 10.5.8 and Mac OS X 10.6 before 10.6.4,
allow remote attackers to execute arbitrary code or cause a denial of
service (application crash) via a crafted TIFF file that triggers a
heap-based buffer overflow.");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_xref(name:"URL", value:"http://www.remotesensing.org/libtiff/v3.9.3.html");
  script_xref(name:"URL", value:"http://support.apple.com/kb/HT4196");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/313da7dc-763b-11df-bcce-0018f3e2eb82.html");

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

bver = portver(pkg:"tiff");
if(!isnull(bver) && revcomp(a:bver, b:"3.9.3")<0) {
  txt += 'Package tiff version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"linux-tiff");
if(!isnull(bver) && revcomp(a:bver, b:"3.9.3")<0) {
  txt += 'Package linux-tiff version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}