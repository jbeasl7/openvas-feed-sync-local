# SPDX-FileCopyrightText: 2010 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.68513");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2010-11-17 03:33:48 +0100 (Wed, 17 Nov 2010)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2010-1780", "CVE-2010-1807", "CVE-2010-1812", "CVE-2010-1814", "CVE-2010-1815", "CVE-2010-3113", "CVE-2010-3114", "CVE-2010-3115", "CVE-2010-3116", "CVE-2010-3255", "CVE-2010-3257", "CVE-2010-3259");
  script_name("FreeBSD Ports: webkit-gtk2");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following package is affected: webkit-gtk2

CVE-2010-1780
Use-after-free vulnerability in WebKit in Apple Safari before 5.0.1 on
Mac OS X 10.5 through 10.6 and Windows, and before 4.1.1 on Mac OS X
10.4, allows remote attackers to execute arbitrary code or cause a
denial of service (application crash) via vectors related to element
focus.

CVE-2010-1807
WebKit in Apple Safari 4.x before 4.1.2 and 5.x before 5.0.2, and
Android before 2.2, does not properly validate floating-point data,
which allows remote attackers to execute arbitrary code or cause a
denial of service (application crash) via a crafted HTML document.

CVE-2010-1812
Use-after-free vulnerability in WebKit in Apple iOS before 4.1 on the
iPhone and iPod touch allows remote attackers to execute arbitrary
code or cause a denial of service (application crash) via vectors
involving selections.

CVE-2010-1814
WebKit in Apple iOS before 4.1 on the iPhone and iPod touch allows
remote attackers to execute arbitrary code or cause a denial of
service (memory corruption and application crash) via vectors
involving form menus.

CVE-2010-1815
Use-after-free vulnerability in WebKit in Apple iOS before 4.1 on the
iPhone and iPod touch allows remote attackers to execute arbitrary
code or cause a denial of service (application crash) via vectors
involving scrollbars.

CVE-2010-3113
Google Chrome before 5.0.375.127 does not properly handle SVG
documents, which allows remote attackers to cause a denial of service
(memory corruption) or possibly have unspecified other impact via
unknown vectors.

CVE-2010-3114
The text-editing implementation in Google Chrome before 5.0.375.127
does not properly perform casts, which has unspecified impact and
attack vectors.

CVE-2010-3115
Google Chrome before 5.0.375.127 does not properly implement the
history feature, which might allow remote attackers to spoof the
address bar via unspecified vectors.

CVE-2010-3116
Google Chrome before 5.0.375.127 does not properly process MIME types,
which allows remote attackers to cause a denial of service (memory
corruption) or possibly have unspecified other impact via unknown
vectors.

CVE-2010-3257
Google Chrome before 6.0.472.53 does not properly perform focus
handling, which allows remote attackers to cause a denial of service
or possibly have unspecified other impact via unknown vectors, related
to a 'stale pointer' issue.

CVE-2010-3259
Google Chrome before 6.0.472.53 does not properly restrict read access
to images, which allows remote attackers to bypass the Same Origin
Policy and obtain potentially sensitive information via unspecified
vectors.");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_xref(name:"URL", value:"http://gitorious.org/webkitgtk/stable/blobs/master/WebKit/gtk/NEWS");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/e5090d2a-dbbe-11df-82f8-0015f2db7bde.html");

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

bver = portver(pkg:"webkit-gtk2");
if(!isnull(bver) && revcomp(a:bver, b:"1.2.5")<0) {
  txt += 'Package webkit-gtk2 version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}