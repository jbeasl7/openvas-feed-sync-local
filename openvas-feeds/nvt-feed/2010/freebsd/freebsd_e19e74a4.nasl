# SPDX-FileCopyrightText: 2010 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.67863");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2010-08-21 08:54:16 +0200 (Sat, 21 Aug 2010)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2010-0209", "CVE-2010-2188", "CVE-2010-2213", "CVE-2010-2214", "CVE-2010-2215", "CVE-2010-2216");
  script_name("FreeBSD Ports: linux-flashplugin");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following packages are affected:

  linux-flashplugin
   linux-f8-flashplugin
   linux-f10-flashplugin

CVE-2010-0209
Adobe Flash Player before 9.0.280 and 10.x before 10.1.82.76, and
Adobe AIR before 2.0.3, allows attackers to execute arbitrary code or
cause a denial of service (memory corruption) via unspecified vectors,
a different vulnerability than CVE-2010-2213, CVE-2010-2214, and
CVE-2010-2216.
CVE-2010-2188
Adobe Flash Player before 9.0.277.0 and 10.x before 10.1.53.64, and
Adobe AIR before 2.0.2.12610, allows attackers to cause a denial of
service (memory corruption) or possibly execute arbitrary code by
calling the ActionScript native object 2200 connect method multiple
times with different arguments, a different vulnerability than
CVE-2010-2160, CVE-2010-2165, CVE-2010-2166, CVE-2010-2171,
CVE-2010-2175, CVE-2010-2176, CVE-2010-2177, CVE-2010-2178,
CVE-2010-2180, CVE-2010-2182, CVE-2010-2184, and CVE-2010-2187.
CVE-2010-2213
Adobe Flash Player before 9.0.280 and 10.x before 10.1.82.76, and
Adobe AIR before 2.0.3, allows attackers to execute arbitrary code or
cause a denial of service (memory corruption) via unspecified vectors,
a different vulnerability than CVE-2010-0209, CVE-2010-2214, and
CVE-2010-2216.
CVE-2010-2214
Adobe Flash Player before 9.0.280 and 10.x before 10.1.82.76, and
Adobe AIR before 2.0.3, allows attackers to execute arbitrary code or
cause a denial of service (memory corruption) via unspecified vectors,
a different vulnerability than CVE-2010-0209, CVE-2010-2213, and
CVE-2010-2216.
CVE-2010-2215
Adobe Flash Player before 9.0.280 and 10.x before 10.1.82.76, and
Adobe AIR before 2.0.3, allows attackers to trick a user into (1)
selecting a link or (2) completing a dialog, related to a
'click-jacking' issue.
CVE-2010-2216
Adobe Flash Player before 9.0.280 and 10.x before 10.1.82.76, and
Adobe AIR before 2.0.3, allows attackers to execute arbitrary code or
cause a denial of service (memory corruption) via unspecified vectors,
a different vulnerability than CVE-2010-0209, CVE-2010-2213, and
CVE-2010-2214.");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_xref(name:"URL", value:"http://www.adobe.com/support/security/bulletins/apsb10-16.html");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/e19e74a4-a712-11df-b234-001b2134ef46.html");

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

bver = portver(pkg:"linux-flashplugin");
if(!isnull(bver) && revcomp(a:bver, b:"9.0r280")<0) {
  txt += 'Package linux-flashplugin version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"linux-f8-flashplugin");
if(!isnull(bver) && revcomp(a:bver, b:"10.1r82")<0) {
  txt += 'Package linux-f8-flashplugin version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"linux-f10-flashplugin");
if(!isnull(bver) && revcomp(a:bver, b:"10.1r82")<0) {
  txt += 'Package linux-f10-flashplugin version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}