# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.52417");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-09-04 20:41:11 +0200 (Thu, 04 Sep 2008)");
  script_cve_id("CVE-2004-0691", "CVE-2004-0692", "CVE-2004-0693");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("FreeBSD Ports: qt");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following package is affected: qt

CVE-2004-0691
Heap-based buffer overflow in the BMP image format parser for the QT
library (qt3) before 3.3.3 allows remote attackers to cause a denial
of service (application crash) and possibly execute arbitrary code.

CVE-2004-0692
The XPM parser in the QT library (qt3) before 3.3.3 allows remote
attackers to cause a denial of service (application crash) via a
malformed image file that triggers a null dereference, a different
vulnerability than CVE-2004-0693.

CVE-2004-0693
The GIF parser in the QT library (qt3) before 3.3.3 allows remote
attackers to cause a denial of service (application crash) via a
malformed image file that triggers a null dereference, a different
vulnerability than CVE-2004-0692.");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_xref(name:"URL", value:"http://www.trolltech.com/developer/changes/changes-3.3.3.html");
  script_xref(name:"URL", value:"http://scary.beasts.org/security/CESA-2004-004.txt");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/ebffe27a-f48c-11d8-9837-000c41e2cdad.html");

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

bver = portver(pkg:"qt");
if(!isnull(bver) && revcomp(a:bver, b:"3.3.3")<0) {
  txt += 'Package qt version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}