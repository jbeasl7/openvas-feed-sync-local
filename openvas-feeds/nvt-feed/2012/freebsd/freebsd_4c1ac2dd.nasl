# SPDX-FileCopyrightText: 2012 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.71526");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_cve_id("CVE-2012-3812");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2012-08-10 03:22:17 -0400 (Fri, 10 Aug 2012)");
  script_name("FreeBSD Ports: asterisk");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following packages are affected:

  asterisk
   asterisk18

CVE-2012-3812
Double free vulnerability in apps/app_voicemail.c in Asterisk Open
Source 1.8.x before 1.8.13.1 and 10.x before 10.5.2, Certified
Asterisk 1.8.11-certx before 1.8.11-cert4, and Asterisk Digiumphones
10.x.x-digiumphones before 10.5.2-digiumphones allows remote
authenticated users to cause a denial of service (daemon crash) by
establishing multiple voicemail sessions and accessing both the Urgent
mailbox and the INBOX mailbox.");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_xref(name:"URL", value:"http://downloads.digium.com/pub/security/AST-2012-011.html");
  script_xref(name:"URL", value:"http://downloads.digium.com/pub/security/AST-2012-012.html");
  script_xref(name:"URL", value:"https://www.asterisk.org/security");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/4c1ac2dd-c788-11e1-be25-14dae9ebcf89.html");

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

bver = portver(pkg:"asterisk");
if(!isnull(bver) && revcomp(a:bver, b:"10")>0 && revcomp(a:bver, b:"10.5.2")<0) {
  txt += "Package asterisk version " + bver + " is installed which is known to be vulnerable.\n";
  vuln = TRUE;
}
bver = portver(pkg:"asterisk18");
if(!isnull(bver) && revcomp(a:bver, b:"1.8")>0 && revcomp(a:bver, b:"1.8.13.1")<0) {
  txt += "Package asterisk18 version " + bver + " is installed which is known to be vulnerable.\n";
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}