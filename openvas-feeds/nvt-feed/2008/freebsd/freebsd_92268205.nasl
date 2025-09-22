# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.52354");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-09-04 20:41:11 +0200 (Thu, 04 Sep 2008)");
  script_cve_id("CVE-2004-0884");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_name("FreeBSD Ports: cyrus-sasl");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following package is affected: cyrus-sasl

CVE-2004-0884
The (1) libsasl and (2) libsasl2 libraries in Cyrus-SASL 2.1.18 and
earlier trust the SASL_PATH environment variable to find all
available SASL plug-ins, which allows local users to execute arbitrary
code by modifying the SASL_PATH to point to malicious programs.");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_xref(name:"URL", value:"https://bugzilla.andrew.cmu.edu/cgi-bin/cvsweb.cgi/src/sasl/lib/common.c#rev1.104");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/11347");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/92268205-1947-11d9-bc4a-000c41e2cdad.html");

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

bver = portver(pkg:"cyrus-sasl");
if(!isnull(bver) && revcomp(a:bver, b:"1.5.28_3")<=0) {
  txt += 'Package cyrus-sasl version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
if(!isnull(bver) && revcomp(a:bver, b:"2")>=0 && revcomp(a:bver, b:"2.1.19")<=0) {
  txt += 'Package cyrus-sasl version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}