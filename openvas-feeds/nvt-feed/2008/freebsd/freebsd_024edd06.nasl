# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.60227");
  script_version("2023-07-26T05:05:08+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:08 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-09-04 20:41:11 +0200 (Thu, 04 Sep 2008)");
  script_cve_id("CVE-2007-6531", "CVE-2007-6532");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("FreeBSD Ports: xfce4-panel, libxfce4gui");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following packages are affected:

  xfce4-panel
   libxfce4gui

CVE-2007-6531
Stack-based buffer overflow in the Panel (xfce4-panel) component in
Xfce before 4.4.2 might allow remote attackers to execute arbitrary
code via Launcher tooltips.  NOTE: a second buffer overflow
(over-read) in the xfce_mkdirhier function was also reported, but it
might not be exploitable for a crash or code execution, so it is not a
vulnerability.

CVE-2007-6532
Double-free vulnerability in the Widget Library (libxfcegui4) in Xfce
before 4.4.2 might allow remote attackers to execute arbitrary code
via unknown vectors related to the 'cliend id, program name and
working directory in session management.'");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_xref(name:"URL", value:"http://www.xfce.org/documentation/changelogs/4.4.2");
  script_xref(name:"URL", value:"http://www.gentoo.org/security/en/glsa/glsa-200801-06.xml");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/024edd06-c933-11dc-810c-0016179b2dd5.html");

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

bver = portver(pkg:"xfce4-panel");
if(!isnull(bver) && revcomp(a:bver, b:"4.4.1_1")>0) {
  txt += 'Package xfce4-panel version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"libxfce4gui");
if(!isnull(bver) && revcomp(a:bver, b:"4.4.1_1")>0) {
  txt += 'Package libxfce4gui version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}