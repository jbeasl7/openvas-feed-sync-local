# SPDX-FileCopyrightText: 2010 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.67294");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2010-04-21 03:31:17 +0200 (Wed, 21 Apr 2010)");
  script_cve_id("CVE-2010-0436");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_name("FreeBSD Ports: kdebase");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following packages are affected:

  kdebase
   kdebase-workspace

CVE-2010-0436
Race condition in backend/ctrl.c in KDM in KDE Software Compilation
(SC) 2.2.0 through 4.4.2 allows local users to change the permissions
of arbitrary files, and consequently gain privileges, by blocking the
removal of a certain directory that contains a control socket, related
to improper interaction with ksm.");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_xref(name:"URL", value:"http://www.kde.org/info/security/advisory-20100413-1.txt");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/3987c5d1-47a9-11df-a0d5-0016d32f24fb.html");

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

bver = portver(pkg:"kdebase");
if(!isnull(bver) && revcomp(a:bver, b:"4")<0) {
  txt += 'Package kdebase version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"kdebase-workspace");
if(!isnull(bver) && revcomp(a:bver, b:"4.3.5_1")<=0) {
  txt += 'Package kdebase-workspace version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}