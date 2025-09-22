# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.52401");
  script_version("2024-02-05T05:05:38+0000");
  script_tag(name:"last_modification", value:"2024-02-05 05:05:38 +0000 (Mon, 05 Feb 2024)");
  script_tag(name:"creation_date", value:"2008-09-04 20:41:11 +0200 (Thu, 04 Sep 2008)");
  script_cve_id("CVE-2004-0642", "CVE-2004-0643", "CVE-2004-0772");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-02-02 15:27:06 +0000 (Fri, 02 Feb 2024)");
  script_name("FreeBSD Ports: krb5");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following package is affected: krb5

CVE-2004-0642
Double-free vulnerabilities in the error handling code for ASN.1
decoders in the (1) Key Distribution Center (KDC) library and (2)
client library for MIT Kerberos 5 (krb5) 1.3.4 and earlier may allow
remote attackers to execute arbitrary code.

CVE-2004-0643
Double-free vulnerability in the krb5_rd_cred function for MIT
Kerberos 5 (krb5) 1.3.1 and earlier may allow local users to execute
arbitrary code.

CVE-2004-0772
Double-free vulnerabilities in error handling code in krb524d for MIT
Kerberos 5 (krb5) 1.2.8 and earlier may allow remote attackers to
execute arbitrary code.");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_xref(name:"URL", value:"http://web.mit.edu/kerberos/advisories/MITKRB5-SA-2004-002-dblfree.txt");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/86a98b57-fb8e-11d8-9343-000a95bc6fae.html");

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

bver = portver(pkg:"krb5");
if(!isnull(bver) && revcomp(a:bver, b:"1.3.4_1")<=0) {
  txt += 'Package krb5 version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}