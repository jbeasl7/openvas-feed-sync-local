# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.52220");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-09-04 20:41:11 +0200 (Thu, 04 Sep 2008)");
  script_cve_id("CVE-2004-1025", "CVE-2004-1026");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("FreeBSD Ports: imlib");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following packages are affected:

  imlib
   imlib2

CVE-2004-1025
Multiple heap-based buffer overflows in imlib 1.9.14 and earlier,
which is used by gkrellm and several window managers, allow remote
attackers to cause a denial of service (application crash) and execute
arbitrary code via certain image files.

CVE-2004-1026
Multiple integer overflows in the image handler for imlib 1.9.14 and
earlier, which is used by gkrellm and several window managers, allow
remote attackers to cause a denial of service (application crash) and
execute arbitrary code via certain image files.");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_xref(name:"URL", value:"https://bugzilla.fedora.us/show_bug.cgi?id=2051#c11");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/11830");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/bugzilla/show_bug.cgi?id=138516");
  script_xref(name:"URL", value:"http://cvs.sourceforge.net/viewcvs.py/enlightenment/e17/libs/imlib2/src/modules/loaders/loader_xpm.c#rev1.3");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/2001103a-6bbd-11d9-851d-000a95bc6fae.html");

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

bver = portver(pkg:"imlib");
if(!isnull(bver) && revcomp(a:bver, b:"1.9.15_2")<0) {
  txt += 'Package imlib version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"imlib2");
if(!isnull(bver) && revcomp(a:bver, b:"1.1.2_1")<0) {
  txt += 'Package imlib2 version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}