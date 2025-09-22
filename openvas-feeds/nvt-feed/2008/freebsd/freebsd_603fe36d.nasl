# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.52423");
  script_version("2024-01-29T05:05:18+0000");
  script_tag(name:"last_modification", value:"2024-01-29 05:05:18 +0000 (Mon, 29 Jan 2024)");
  script_tag(name:"creation_date", value:"2008-09-04 20:41:11 +0200 (Thu, 04 Sep 2008)");
  script_cve_id("CVE-2004-0689", "CVE-2004-0690");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-01-26 17:06:00 +0000 (Fri, 26 Jan 2024)");
  script_name("FreeBSD Ports: kdelibs");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following package is affected: kdelibs

CVE-2004-0689
KDE before 3.3.0 does not properly handle when certain symbolic links
point to 'stale' locations, which could allow local users to create or
truncate arbitrary files.

CVE-2004-0690
The DCOPServer in KDE 3.2.3 and earlier allows local users to gain
unauthorized access via a symlink attack on DCOP files in the /tmp
directory.");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_xref(name:"URL", value:"http://www.kde.org/info/security/advisory-20040811-1.txt");
  script_xref(name:"URL", value:"http://www.kde.org/info/security/advisory-20040811-2.txt");
  script_xref(name:"URL", value:"ftp://ftp.kde.org/pub/kde/security_patches/post-3.2.3-kdelibs-kstandarddirs.patch");
  script_xref(name:"URL", value:"ftp://ftp.kde.org/pub/kde/security_patches/post-3.2.3-kdelibs-dcopserver.patch");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/603fe36d-ec9d-11d8-b913-000c41e2cdad.html");

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

bver = portver(pkg:"kdelibs");
if(!isnull(bver) && revcomp(a:bver, b:"3.2.3_3")<=0) {
  txt += 'Package kdelibs version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}