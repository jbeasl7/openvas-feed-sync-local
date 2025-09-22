# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.52385");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-09-04 20:41:11 +0200 (Thu, 04 Sep 2008)");
  script_cve_id("CVE-2004-0782", "CVE-2004-0783", "CVE-2004-0788");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("FreeBSD Ports: linux-gdk-pixbuf");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following packages are affected:

  linux-gdk-pixbuf
   gtk
   gdk-pixbuf

CVE-2004-0782
Integer overflow in pixbuf_create_from_xpm (io-xpm.c) in the XPM image
decoder for gtk+ 2.4.4 (gtk2) and earlier, and gdk-pixbuf before 0.22,
allows remote attackers to execute arbitrary code via certain n_col
and cpp values that enable a heap-based buffer overflow.  NOTE: this
identifier is ONLY for gtk+.  It was incorrectly referenced in an
advisory for a different issue (CVE-2004-0687).

CVE-2004-0783
Stack-based buffer overflow in xpm_extract_color (io-xpm.c) in the XPM
image decoder for gtk+ 2.4.4 (gtk2) and earlier, and gdk-pixbuf before
0.22, may allow remote attackers to execute arbitrary code via a
certain color string.  NOTE: this identifier is ONLY for gtk+.  It was
incorrectly referenced in an advisory for a different issue
(CVE-2004-0688).

CVE-2004-0788
Integer overflow in the ICO image decoder for (1) gdk-pixbuf before
0.22 and (2) gtk2 before 2.2.4 allows remote attackers to cause a
denial of service (application crash) via a crafted ICO file.");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_xref(name:"URL", value:"http://scary.beasts.org/security/CESA-2004-005.txt");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/3d1e9267-073f-11d9-b45d-000c41e2cdad.html");

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

bver = portver(pkg:"linux-gdk-pixbuf");
if(!isnull(bver) && revcomp(a:bver, b:"0.22.0.11.3.5")<0) {
  txt += 'Package linux-gdk-pixbuf version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"gtk");
if(!isnull(bver) && revcomp(a:bver, b:"2.0")>=0 && revcomp(a:bver, b:"2.4.9_1")<0) {
  txt += 'Package gtk version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"gdk-pixbuf");
if(!isnull(bver) && revcomp(a:bver, b:"0.22.0_2")<0) {
  txt += 'Package gdk-pixbuf version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}