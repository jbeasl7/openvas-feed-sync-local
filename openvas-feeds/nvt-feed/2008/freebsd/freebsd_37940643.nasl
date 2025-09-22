# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.61956");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-12-03 18:25:22 +0100 (Wed, 03 Dec 2008)");
  script_cve_id("CVE-2008-2940", "CVE-2008-2941");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_name("FreeBSD Ports: hplip");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following package is affected: hplip

CVE-2008-2940
The alert-mailing implementation in HP Linux Imaging and Printing
(HPLIP) 1.6.7 allows local users to gain privileges and send e-mail
messages from the root account via vectors related to the setalerts
message, and lack of validation of the device URI associated with an
event message.

CVE-2008-2941
The hpssd message parser in hpssd.py in HP Linux Imaging and Printing
(HPLIP) 1.6.7 allows local users to cause a denial of service (process
stop) via a crafted packet, as demonstrated by sending 'msg=0' to TCP
port 2207.");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_xref(name:"URL", value:"https://rhn.redhat.com/errata/RHSA-2008-0818.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/30683");
  script_xref(name:"URL", value:"http://secunia.com/advisories/31470");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/37940643-be1b-11dd-a578-0030843d3802.html");

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

bver = portver(pkg:"hplip");
if(!isnull(bver) && revcomp(a:bver, b:"2.8.2_3")<0) {
  txt += 'Package hplip version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}