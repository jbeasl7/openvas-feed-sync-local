# SPDX-FileCopyrightText: 2010 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.67295");
  script_cve_id("CVE-2010-2272", "CVE-2010-2273", "CVE-2010-2274", "CVE-2010-2275", "CVE-2010-2276");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2010-04-21 03:31:17 +0200 (Wed, 21 Apr 2010)");
  script_name("FreeBSD Ports: dojo");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following package is affected: dojo");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_xref(name:"URL", value:"http://dojotoolkit.org/blog/post/dylan/2010/03/dojo-security-advisory/");
  script_xref(name:"URL", value:"http://osdir.com/ml/bugtraq.security/2010-03/msg00133.html");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/1003-exploits/dojo-xss.txt");
  script_xref(name:"URL", value:"http://secunia.com/advisories/38964");
  script_xref(name:"URL", value:"http://www.gdssecurity.com/l/b/2010/03/12/multiple-dom-based-xss-in-dojo-toolkit-sdk/");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/805603a1-3e7a-11df-a5a1-0050568452ac.html");

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

bver = portver(pkg:"dojo");
if(!isnull(bver) && revcomp(a:bver, b:"1.4.2")<0) {
  txt += 'Package dojo version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}