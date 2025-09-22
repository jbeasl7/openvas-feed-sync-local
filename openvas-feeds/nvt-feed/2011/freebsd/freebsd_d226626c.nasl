# SPDX-FileCopyrightText: 2011 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.69763");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2011-08-03 04:36:20 +0200 (Wed, 03 Aug 2011)");
  script_cve_id("CVE-2011-0579", "CVE-2011-0618", "CVE-2011-0619", "CVE-2011-0620", "CVE-2011-0621", "CVE-2011-0622", "CVE-2011-0623", "CVE-2011-0624", "CVE-2011-0625", "CVE-2011-0626", "CVE-2011-0627");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("FreeBSD Ports: linux-flashplugin");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following packages are affected:

  linux-flashplugin
   linux-f10-flashplugin

CVE-2011-0579
Adobe Flash Player before 10.3.181.14 on Windows, Mac OS X, Linux, and
Solaris and before 10.3.185.21 on Android allows attackers to obtain
sensitive information via unspecified vectors.

CVE-2011-0618
Integer overflow in Adobe Flash Player before 10.3.181.14 on Windows,
Mac OS X, Linux, and Solaris and before 10.3.185.21 on Android allows
attackers to execute arbitrary code via unspecified vectors.

CVE-2011-0619
Adobe Flash Player before 10.3.181.14 on Windows, Mac OS X, Linux, and
Solaris and before 10.3.185.21 on Android allows attackers to execute
arbitrary code or cause a denial of service (memory corruption) via
unspecified vectors, a different vulnerability than CVE-2011-0620,

CVE-2011-0621, and CVE-2011-0622.
CVE-2011-0620
Adobe Flash Player before 10.3.181.14 on Windows, Mac OS X, Linux, and
Solaris and before 10.3.185.21 on Android allows attackers to execute
arbitrary code or cause a denial of service (memory corruption) via
unspecified vectors, a different vulnerability than CVE-2011-0619,

CVE-2011-0621, and CVE-2011-0622.
CVE-2011-0621
Adobe Flash Player before 10.3.181.14 on Windows, Mac OS X, Linux, and
Solaris and before 10.3.185.21 on Android allows attackers to execute
arbitrary code or cause a denial of service (memory corruption) via
unspecified vectors, a different vulnerability than CVE-2011-0619,

Text truncated. Please see the references for more information.");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_xref(name:"URL", value:"http://www.adobe.com/support/security/bulletins/apsb11-12.html");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/d226626c-857f-11e0-95cc-001b2134ef46.html");

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
if(!isnull(bver) && revcomp(a:bver, b:"9.0r289")<=0) {
  txt += 'Package linux-flashplugin version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"linux-f10-flashplugin");
if(!isnull(bver) && revcomp(a:bver, b:"10.3r181.14")<0) {
  txt += 'Package linux-f10-flashplugin version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}