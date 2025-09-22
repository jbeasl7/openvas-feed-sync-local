# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.891979");
  script_cve_id("CVE-2014-6051", "CVE-2014-6052", "CVE-2014-6053", "CVE-2014-6054", "CVE-2014-6055", "CVE-2016-9941", "CVE-2016-9942", "CVE-2018-15126", "CVE-2018-15127", "CVE-2018-20019", "CVE-2018-20020", "CVE-2018-20021", "CVE-2018-20022", "CVE-2018-20023", "CVE-2018-20024", "CVE-2018-20748", "CVE-2018-20749", "CVE-2018-20750", "CVE-2018-6307", "CVE-2018-7225", "CVE-2019-15681");
  script_tag(name:"creation_date", value:"2019-10-31 03:00:34 +0000 (Thu, 31 Oct 2019)");
  script_version("2024-02-02T05:06:07+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:07 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-01-07 21:11:03 +0000 (Mon, 07 Jan 2019)");

  script_name("Debian: Security Advisory (DLA-1979-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8");

  script_xref(name:"Advisory-ID", value:"DLA-1979-1");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2019/DLA-1979-1");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'italc' package(s) announced via the DLA-1979-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been identified in the VNC code of iTALC, a classroom management software. All vulnerabilities referenced below are issues that have originally been reported against Debian source package libvncserver. The italc source package in Debian ships a custom-patched version of libvncserver, thus libvncserver's security fixes required porting over.

CVE-2014-6051

Integer overflow in the MallocFrameBuffer function in vncviewer.c in LibVNCServer allowed remote VNC servers to cause a denial of service (crash) and possibly executed arbitrary code via an advertisement for a large screen size, which triggered a heap-based buffer overflow.

CVE-2014-6052

The HandleRFBServerMessage function in libvncclient/rfbproto.c in LibVNCServer did not check certain malloc return values, which allowed remote VNC servers to cause a denial of service (application crash) or possibly execute arbitrary code by specifying a large screen size in a (1) FramebufferUpdate, (2) ResizeFrameBuffer, or (3) PalmVNCReSizeFrameBuffer message.

CVE-2014-6053

The rfbProcessClientNormalMessage function in libvncserver/rfbserver.c in LibVNCServer did not properly handle attempts to send a large amount of ClientCutText data, which allowed remote attackers to cause a denial of service (memory consumption or daemon crash) via a crafted message that was processed by using a single unchecked malloc.

CVE-2014-6054

The rfbProcessClientNormalMessage function in libvncserver/rfbserver.c in LibVNCServer allowed remote attackers to cause a denial of service (divide-by-zero error and server crash) via a zero value in the scaling factor in a (1) PalmVNCSetScaleFactor or (2) SetScale message.

CVE-2014-6055

Multiple stack-based buffer overflows in the File Transfer feature in rfbserver.c in LibVNCServer allowed remote authenticated users to cause a denial of service (crash) and possibly execute arbitrary code via a (1) long file or (2) directory name or the (3) FileTime attribute in a rfbFileTransferOffer message.

CVE-2016-9941

Heap-based buffer overflow in rfbproto.c in LibVNCClient in LibVNCServer allowed remote servers to cause a denial of service (application crash) or possibly execute arbitrary code via a crafted FramebufferUpdate message containing a subrectangle outside of the client drawing area.

CVE-2016-9942

Heap-based buffer overflow in ultra.c in LibVNCClient in LibVNCServer allowed remote servers to cause a denial of service (application crash) or possibly execute arbitrary code via a crafted FramebufferUpdate message with the Ultra type tile, such that the LZO payload decompressed length exceeded what is specified by the tile dimensions.

CVE-2018-6307

LibVNC contained heap use-after-free vulnerability in server code of file transfer extension that can result remote code execution.

CVE-2018-7225

An issue was discovered in LibVNCServer. rfbProcessClientNormalMessage() in ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'italc' package(s) on Debian 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

release = dpkg_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "DEB8") {

  if(!isnull(res = isdpkgvuln(pkg:"italc-client", ver:"1:2.0.2+dfsg1-2+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"italc-client-dbg", ver:"1:2.0.2+dfsg1-2+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"italc-management-console", ver:"1:2.0.2+dfsg1-2+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"italc-management-console-dbg", ver:"1:2.0.2+dfsg1-2+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"italc-master", ver:"1:2.0.2+dfsg1-2+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"italc-master-dbg", ver:"1:2.0.2+dfsg1-2+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libitalccore", ver:"1:2.0.2+dfsg1-2+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libitalccore-dbg", ver:"1:2.0.2+dfsg1-2+deb8u1", rls:"DEB8"))) {
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
