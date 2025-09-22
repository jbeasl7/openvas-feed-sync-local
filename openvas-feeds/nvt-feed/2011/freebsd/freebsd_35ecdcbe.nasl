# SPDX-FileCopyrightText: 2011 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.68950");
  script_version("2023-11-02T05:05:26+0000");
  script_tag(name:"last_modification", value:"2023-11-02 05:05:26 +0000 (Thu, 02 Nov 2023)");
  script_tag(name:"creation_date", value:"2011-03-05 22:25:39 +0100 (Sat, 05 Mar 2011)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-04 19:21:00 +0000 (Tue, 04 Aug 2020)");
  script_cve_id("CVE-2010-2901", "CVE-2010-4040", "CVE-2010-4042", "CVE-2010-4199", "CVE-2010-4492", "CVE-2010-4493", "CVE-2010-4578", "CVE-2011-0482", "CVE-2011-0778");
  script_name("FreeBSD Ports: webkit-gtk2");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following package is affected: webkit-gtk2

CVE-2010-2901
The rendering implementation in Google Chrome before 5.0.375.125
allows remote attackers to cause a denial of service (memory
corruption) or possibly have unspecified other impact via unknown
vectors.

CVE-2010-4040
Google Chrome before 7.0.517.41 does not properly handle animated GIF
images, which allows remote attackers to cause a denial of service
(memory corruption) or possibly have unspecified other impact via a
crafted image.

CVE-2010-4042
Google Chrome before 7.0.517.41 does not properly handle element maps,
which allows remote attackers to cause a denial of service or possibly
have unspecified other impact via vectors related to 'stale elements.'

CVE-2010-4199
Google Chrome before 7.0.517.44 does not properly perform a cast of an
unspecified variable during processing of an SVG use element, which
allows remote attackers to cause a denial of service or possibly have
unspecified other impact via a crafted SVG document.

CVE-2010-4492
Use-after-free vulnerability in Google Chrome before 8.0.552.215
allows remote attackers to cause a denial of service or possibly have
unspecified other impact via vectors involving SVG animations.

CVE-2010-4493
Use-after-free vulnerability in Google Chrome before 8.0.552.215
allows remote attackers to cause a denial of service via vectors
related to the handling of mouse dragging events.

CVE-2010-4578
Google Chrome before 8.0.552.224 and Chrome OS before 8.0.552.343 do
not properly perform cursor handling, which allows remote attackers to
cause a denial of service or possibly have unspecified other impact
via unknown vectors that lead to 'stale pointers.'

CVE-2011-0482
Google Chrome before 8.0.552.237 and Chrome OS before 8.0.552.344 do
not properly perform a cast of an unspecified variable during handling
of anchors, which allows remote attackers to cause a denial of service
or possibly have unspecified other impact via a crafted HTML document.

CVE-2011-0778
Google Chrome before 9.0.597.84 does not properly restrict drag and
drop operations, which might allow remote attackers to bypass the Same
Origin Policy via unspecified vectors.");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_xref(name:"URL", value:"https://bugs.webkit.org/show_bug.cgi?id=48328");
  script_xref(name:"URL", value:"https://bugs.webkit.org/show_bug.cgi?id=50710");
  script_xref(name:"URL", value:"https://bugs.webkit.org/show_bug.cgi?id=50840");
  script_xref(name:"URL", value:"https://bugs.webkit.org/show_bug.cgi?id=50932");
  script_xref(name:"URL", value:"https://bugs.webkit.org/show_bug.cgi?id=51993");
  script_xref(name:"URL", value:"https://bugs.webkit.org/show_bug.cgi?id=53265");
  script_xref(name:"URL", value:"https://bugs.webkit.org/show_bug.cgi?id=53276");
  script_xref(name:"URL", value:"http://permalink.gmane.org/gmane.os.opendarwin.webkit.gtk/405");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/35ecdcbe-3501-11e0-afcd-0015f2db7bde.html");

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

bver = portver(pkg:"webkit-gtk2");
if(!isnull(bver) && revcomp(a:bver, b:"1.2.7")<0) {
  txt += 'Package webkit-gtk2 version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}