# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.61190");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-09-04 20:41:11 +0200 (Thu, 04 Sep 2008)");
  script_cve_id("CVE-2008-1377", "CVE-2008-1379", "CVE-2008-2360", "CVE-2008-2361", "CVE-2008-2362");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("FreeBSD Ports: xorg-server");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following package is affected: xorg-server

CVE-2008-1377
The (1) SProcRecordCreateContext and (2) SProcRecordRegisterClients
functions in the Record extension and the (3)
SProcSecurityGenerateAuthorization function in the Security extension
in the X server 1.4 in X.Org X11R7.3 allow context-dependent attackers
to execute arbitrary code via requests with crafted length values that
specify an arbitrary number of bytes to be swapped on the heap, which
triggers heap corruption.

CVE-2008-1379
Integer overflow in the fbShmPutImage function in the MIT-SHM
extension in the X server 1.4 in X.Org X11R7.3 allows
context-dependent attackers to read arbitrary process memory via
crafted values for a Pixmap width and height.

CVE-2008-2360
Integer overflow in the AllocateGlyph function in the Render extension
in the X server 1.4 in X.Org X11R7.3 allows context-dependent
attackers to execute arbitrary code via unspecified request fields
that are used to calculate a heap buffer size, which triggers a
heap-based buffer overflow.

CVE-2008-2361
Integer overflow in the ProcRenderCreateCursor function in the Render
extension in the X server 1.4 in X.Org X11R7.3 allows
context-dependent attackers to cause a denial of service (daemon
crash) via unspecified request fields that are used to calculate a
glyph buffer size, which triggers a dereference of unmapped memory.

CVE-2008-2362
Multiple integer overflows in the Render extension in the X server 1.4
in X.Org X11R7.3 allow context-dependent attackers to execute
arbitrary code via a (1) SProcRenderCreateLinearGradient, (2)
SProcRenderCreateRadialGradient, or (3)
SProcRenderCreateConicalGradient request with an invalid field
specifying the number of bytes to swap in the request data, which
triggers heap memory corruption.");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_xref(name:"URL", value:"http://lists.freedesktop.org/archives/xorg/2008-June/036026.html");
  script_xref(name:"URL", value:"http://secunia.com/advisories/30627/");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/800e8bd5-3acb-11dd-8842-001302a18722.html");

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

bver = portver(pkg:"xorg-server");
if(!isnull(bver) && revcomp(a:bver, b:"1.4.2,1")<0) {
  txt += 'Package xorg-server version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}