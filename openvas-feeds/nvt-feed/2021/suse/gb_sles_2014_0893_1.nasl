# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2014.0893.1");
  script_cve_id("CVE-2013-1981", "CVE-2013-1997", "CVE-2013-2004");
  script_tag(name:"creation_date", value:"2021-06-09 14:58:20 +0000 (Wed, 09 Jun 2021)");
  script_version("2024-02-02T05:06:07+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:07 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_name("SUSE: Security Advisory (SUSE-SU-2014:0893-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP1)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2014:0893-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2014/suse-su-20140893-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'xorg-x11-libX11' package(s) announced via the SUSE-SU-2014:0893-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This is a SUSE Linux Enterprise Server 11 SP1 LTSS roll up update of xorg-x11-libX11, fixing security issues.

These issues require connection to a malicious X server to trigger the bugs in client libraries.

Security issues fixed:

 *

 CVE-2013-1981: Multiple integer overflows in X.org libX11 allowed X servers to trigger allocation of insufficient memory and a buffer
 overflow via vectors related to the (1) XQueryFont, (2)
_XF86BigfontQueryFont, (3) XListFontsWithInfo, (4) XGetMotionEvents, (5)
XListHosts, (6) XGetModifierMapping, (7) XGetPointerMapping, (8)
XGetKeyboardMapping, (9) XGetWindowProperty, (10) XGetImage, (11)
LoadColornameDB, (12) XrmGetFileDatabase, (13) _XimParseStringFile,
 or (14) TransFileName functions.

 *

 CVE-2013-1997: Multiple buffer overflows in X.org libX11 allowed X servers to cause a denial of service (crash) and possibly execute arbitrary code via crafted length or index values to the (1)
XAllocColorCells, (2) _XkbReadGetDeviceInfoReply, (3) _XkbReadGeomShapes,
(4) _XkbReadGetGeometryReply, (5) _XkbReadKeySyms, (6) _XkbReadKeyActions,
(7) _XkbReadKeyBehaviors, (8) _XkbReadModifierMap, (9)
_XkbReadExplicitComponents, (10) _XkbReadVirtualModMap, (11)
_XkbReadGetNamesReply, (12) _XkbReadGetMapReply, (13) _XimXGetReadData,
(14) XListFonts, (15) XListExtensions, and (16) XGetFontPath functions.

 *

 CVE-2013-2004: The (1) GetDatabase and (2) _XimParseStringFile functions in X.org libX11 did not restrict the recursion depth when processing directives to include files, which allowed X servers to cause a denial of service (stack consumption) via a crafted file.

Security Issue references:

 * CVE-2013-1981
 * CVE-2013-1997
 * CVE-2013-2004");

  script_tag(name:"affected", value:"'xorg-x11-libX11' package(s) on SUSE Linux Enterprise Server 11-SP1.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "SLES11.0SP1") {

  if(!isnull(res = isrpmvuln(pkg:"xorg-x11-libX11-32bit", rpm:"xorg-x11-libX11-32bit~7.4~5.11.11.7", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xorg-x11-libX11", rpm:"xorg-x11-libX11~7.4~5.11.11.7", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

exit(0);
