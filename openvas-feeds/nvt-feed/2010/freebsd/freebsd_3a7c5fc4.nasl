# SPDX-FileCopyrightText: 2010 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.67998");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2010-10-10 19:35:00 +0200 (Sun, 10 Oct 2010)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2010-2253");
  script_name("FreeBSD Ports: p5-libwww");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following package is affected: p5-libwww

CVE-2010-2253
lwp-download in libwww-perl before 5.835 does not reject downloads to
filenames that begin with a . (dot) character, which allows remote
servers to create or overwrite files via (1) a 3xx redirect to a URL
with a crafted filename or (2) a Content-Disposition header that
suggests a crafted filename, and possibly execute arbitrary code as a
consequence of writing to a dotfile in a home directory.");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_xref(name:"URL", value:"http://cpansearch.perl.org/src/GAAS/libwww-perl-5.836/Changes");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/3a7c5fc4-b50c-11df-977b-ecc31dd8ad06.html");

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

bver = portver(pkg:"p5-libwww");
if(!isnull(bver) && revcomp(a:bver, b:"5.835")<0) {
  txt += 'Package p5-libwww version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}