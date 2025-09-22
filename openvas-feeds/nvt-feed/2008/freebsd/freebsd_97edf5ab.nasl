# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.52128");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-09-04 20:41:11 +0200 (Thu, 04 Sep 2008)");
  script_cve_id("CVE-2005-1108", "CVE-2005-1109");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("FreeBSD Ports: junkbuster");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following packages are affected:

  junkbuster
   junkbuster-zlib

CVE-2005-1108
The ij_untrusted_url function in JunkBuster 2.0.2-r2, with
single-threaded mode enabled, allows remote attackers to overwrite the
referrer field via a crafted HTTP request.

CVE-2005-1109
The filtering of URLs in JunkBuster before 2.0.2-r3 allows remote
attackers to cause a denial of service (application crash) and
possibly execute arbitrary code via heap corruption.");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_xref(name:"URL", value:"http://www.debian.org/security/2005/dsa-713");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/13146");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/13147");
  script_xref(name:"URL", value:"http://www.gentoo.org/security/en/glsa/glsa-200504-11.xml");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/97edf5ab-b319-11d9-837d-000e0c2e438a.html");

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

bver = portver(pkg:"junkbuster");
if(!isnull(bver) && revcomp(a:bver, b:"2.0.2_3")<0) {
  txt += 'Package junkbuster version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"junkbuster-zlib");
if(!isnull(bver) && revcomp(a:bver, b:"0")>0) {
  txt += 'Package junkbuster-zlib version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}