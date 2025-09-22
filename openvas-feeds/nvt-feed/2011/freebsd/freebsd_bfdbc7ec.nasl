# SPDX-FileCopyrightText: 2011 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.69999");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2011-08-03 04:36:20 +0200 (Wed, 03 Aug 2011)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2011-0719");
  script_name("FreeBSD Ports: samba34");

  script_xref(name:"URL", value:"http://www.samba.org/samba/security/CVE-2011-0719.html");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/bfdbc7ec-9c3f-11e0-9bec-6c626dd55a41.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following packages are affected:

  samba34
   samba35

CVE-2011-0719
Samba 3.x before 3.3.15, 3.4.x before 3.4.12, and 3.5.x before 3.5.7
does not perform range checks for file descriptors before use of the
FD_SET macro, which allows remote attackers to cause a denial of
service (stack memory corruption, and infinite loop or daemon crash)
by opening a large number of files, related to (1) Winbind or (2)
smbd.");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

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

bver = portver(pkg:"samba34");
if(!isnull(bver) && revcomp(a:bver, b:"3.4")>0 && revcomp(a:bver, b:"3.4.12")<0) {
  txt += 'Package samba34 version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"samba35");
if(!isnull(bver) && revcomp(a:bver, b:"3.5")>0 && revcomp(a:bver, b:"3.5.7")<0) {
  txt += 'Package samba35 version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}