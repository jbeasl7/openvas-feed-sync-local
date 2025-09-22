# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.52432");
  script_version("2024-01-01T05:05:52+0000");
  script_tag(name:"last_modification", value:"2024-01-01 05:05:52 +0000 (Mon, 01 Jan 2024)");
  script_tag(name:"creation_date", value:"2008-09-04 20:41:11 +0200 (Thu, 04 Sep 2008)");
  script_cve_id("CVE-2004-0176", "CVE-2004-0365", "CVE-2004-0367");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-12-28 15:33:00 +0000 (Thu, 28 Dec 2023)");
  script_name("FreeBSD Ports: ethereal, tethereal");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following packages are affected:
   ethereal
   tethereal

CVE-2004-0176
Multiple buffer overflows in Ethereal 0.8.13 to 0.10.2 allow remote
attackers to cause a denial of service and possibly execute arbitrary
code via the (1) NetFlow, (2) IGAP, (3) EIGRP, (4) PGM, (5) IrDA, (6)
BGP, (7) ISUP, or (8) TCAP dissectors.

CVE-2004-0365
The dissect_attribute_value_pairs function in packet-radius.c for
Ethereal 0.8.13 to 0.10.2 allows remote attackers to cause a denial of
service (crash) via a malformed RADIUS packet that triggers a null
dereference.

CVE-2004-0367
Ethereal 0.10.1 to 0.10.2 allows remote attackers to cause a denial of
service (crash) via a zero-length Presentation protocol selector.");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
software upgrades.");

  script_tag(name:"summary", value:"The remote host is missing an update to the system
as announced in the referenced advisory.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.ethereal.com/appnotes/enpa-sa-00013.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/9952");
  script_xref(name:"URL", value:"http://security.e-matters.de/advisories/032004.html");
  script_xref(name:"URL", value:"http://secunia.com/advisories/11185");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/cdf18ed9-7f4a-11d8-9645-0020ed76ef5a.html");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-bsd.inc");

txt = "";
vuln = FALSE;

bver = portver(pkg:"ethereal");
if(!isnull(bver) && revcomp(a:bver, b:"0.10.3")<0) {
  txt += 'Package ethereal version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"tethereal");
if(!isnull(bver) && revcomp(a:bver, b:"0.10.3")<0) {
  txt += 'Package tethereal version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}