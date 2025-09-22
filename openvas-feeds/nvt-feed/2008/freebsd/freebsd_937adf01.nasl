# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.61918");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-11-24 23:46:43 +0100 (Mon, 24 Nov 2008)");
  script_cve_id("CVE-2008-6510", "CVE-2008-6511", "CVE-2008-6508", "CVE-2009-1595", "CVE-2008-1728", "CVE-2008-6509");
  script_name("FreeBSD Ports: openfire");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following package is affected: openfire");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_xref(name:"URL", value:"http://www.andreas-kurtz.de/advisories/AKADV2008-001-v1.0.txt");
  script_xref(name:"URL", value:"http://www.igniterealtime.org/builds/openfire/docs/latest/changelog.html");
  script_xref(name:"URL", value:"http://secunia.com/Advisories/32478/");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/937adf01-b64a-11dd-a55e-00163e000016.html");

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

bver = portver(pkg:"openfire");
if(!isnull(bver) && revcomp(a:bver, b:"3.6.1")<0) {
  txt += 'Package openfire version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}