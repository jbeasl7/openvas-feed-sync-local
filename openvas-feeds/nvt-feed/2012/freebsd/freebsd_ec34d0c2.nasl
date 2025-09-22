# SPDX-FileCopyrightText: 2012 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.72503");
  script_cve_id("CVE-2012-3363");
  script_version("2024-02-16T05:06:55+0000");
  script_tag(name:"last_modification", value:"2024-02-16 05:06:55 +0000 (Fri, 16 Feb 2024)");
  script_tag(name:"creation_date", value:"2012-10-22 08:43:21 -0400 (Mon, 22 Oct 2012)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-02-15 03:20:09 +0000 (Thu, 15 Feb 2024)");
  script_name("FreeBSD Ports: ZendFramework");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following package is affected: ZendFramework");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_xref(name:"URL", value:"https://www.sec-consult.com/files/20120626-0_zend_framework_xxe_injection.txt");
  script_xref(name:"URL", value:"http://framework.zend.com/security/advisory/ZF2012-01");
  script_xref(name:"URL", value:"http://framework.zend.com/security/advisory/ZF2012-02");
  script_xref(name:"URL", value:"http://www.openwall.com/lists/oss-security/2012/06/26/2");
  script_xref(name:"URL", value:"https://secunia.com/advisories/49665/");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/ec34d0c2-1799-11e2-b4ab-000c29033c32.html");

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

bver = portver(pkg:"ZendFramework");
if(!isnull(bver) && revcomp(a:bver, b:"1.11.13")<0) {
  txt += "Package ZendFramework version " + bver + " is installed which is known to be vulnerable.\n";
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}