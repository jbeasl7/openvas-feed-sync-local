# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2014.0881.1");
  script_cve_id("CVE-2013-1984", "CVE-2013-1985", "CVE-2013-1986", "CVE-2013-1988", "CVE-2013-1990", "CVE-2013-1991", "CVE-2013-1992", "CVE-2013-1995", "CVE-2013-1996", "CVE-2013-1998", "CVE-2013-1999", "CVE-2013-2000", "CVE-2013-2001", "CVE-2013-2003", "CVE-2013-2063", "CVE-2013-6462", "CVE-2014-0209", "CVE-2014-0210", "CVE-2014-0211");
  script_tag(name:"creation_date", value:"2021-06-09 14:58:20 +0000 (Wed, 09 Jun 2021)");
  script_version("2024-02-02T14:37:48+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:48 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_name("SUSE: Security Advisory (SUSE-SU-2014:0881-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP1)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2014:0881-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2014/suse-su-20140881-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'xorg-x11-libs' package(s) announced via the SUSE-SU-2014:0881-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This is a SUSE Linux Enterprise Server 11 SP1 LTSS roll up update of xorg-x11-libs, fixing security issues and some bugs.

These issues require connection to a malicious X server to trigger the bugs in client libraries.

Security issues fixed:

 * CVE-2013-1984: Multiple integer overflows in X.org libXi allowed X
 servers to trigger allocation of insufficient memory and a buffer
 overflow via vectors related to the (1) XGetDeviceControl, (2)
XGetFeedbackControl, (3) XGetDeviceDontPropagateList, (4)
XGetDeviceMotionEvents, (5) XIGetProperty, (6) XIGetSelectedEvents, (7)
XGetDeviceProperties, and (8) XListInputDevices functions.
 * CVE-2013-1985: Integer overflow in X.org libXinerama allowed X
 servers to trigger allocation of insufficient memory and a buffer
 overflow via vectors related to the XineramaQueryScreens function.
 * CVE-2013-1986: Multiple integer overflows in X.org libXrandr allowed
 X servers to trigger allocation of insufficient memory and a buffer
 overflow via vectors related to the (1) XRRQueryOutputProperty and
(2) XRRQueryProviderProperty functions.
 * CVE-2013-1988: Multiple integer overflows in X.org libXRes allowed X
 servers to trigger allocation of insufficient memory and a buffer
 overflow via vectors related to the (1) XResQueryClients and (2)
XResQueryClientResources functions.
 * CVE-2013-1990: Multiple integer overflows in X.org libXvMC allowed X
 servers to trigger allocation of insufficient memory and a buffer
 overflow via vectors related to the (1) XvMCListSurfaceTypes and (2)
XvMCListSubpictureTypes functions.
 * CVE-2013-1991: Multiple integer overflows in X.org libXxf86dga
 allowed X servers to trigger allocation of insufficient memory and a
 buffer overflow via vectors related to the (1) XDGAQueryModes and
 (2) XDGASetMode functions.
 * CVE-2013-1992: Multiple integer overflows in X.org libdmx allowed X
 servers to trigger allocation of insufficient memory and a buffer
 overflow via vectors related to the (1) DMXGetScreenAttributes, (2)
DMXGetWindowAttributes, and (3) DMXGetInputAttributes functions.
 * CVE-2013-1995: X.org libXi allowed X servers to trigger allocation
 of insufficient memory and a buffer overflow via vectors related to
 an unexpected sign extension in the XListInputDevices function.
 * CVE-2013-1996: X.org libFS allowed X servers to trigger allocation
 of insufficient memory and a buffer overflow via vectors related to
 an unexpected sign extension in the FSOpenServer function.
 * CVE-2013-1998: Multiple buffer overflows in X.org libXi allowed X
 servers to cause a denial of service (crash) and possibly execute
 arbitrary code via crafted length or index values to the (1)
 XGetDeviceButtonMapping, (2) XIPassiveGrabDevice, and (3)
 XQueryDeviceState functions.
 * CVE-2013-1999: Buffer overflow in X.org libXvMC allowed X servers to
 cause a denial of service (crash) and possibly execute arbitrary
 code via crafted ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'xorg-x11-libs' package(s) on SUSE Linux Enterprise Server 11-SP1.");

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

  if(!isnull(res = isrpmvuln(pkg:"xorg-x11-libs-32bit", rpm:"xorg-x11-libs-32bit~7.4~8.26.42.4", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xorg-x11-libs", rpm:"xorg-x11-libs~7.4~8.26.42.4", rls:"SLES11.0SP1"))) {
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
