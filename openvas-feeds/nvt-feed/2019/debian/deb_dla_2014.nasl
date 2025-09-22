# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.892014");
  script_cve_id("CVE-2014-6053", "CVE-2018-7225", "CVE-2019-15681");
  script_tag(name:"creation_date", value:"2019-11-30 03:00:09 +0000 (Sat, 30 Nov 2019)");
  script_version("2024-02-02T05:06:07+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:07 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-03-19 15:20:21 +0000 (Mon, 19 Mar 2018)");

  script_name("Debian: Security Advisory (DLA-2014-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8");

  script_xref(name:"Advisory-ID", value:"DLA-2014-1");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2019/DLA-2014-1");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'vino' package(s) announced via the DLA-2014-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been identified in the VNC code of vino, a desktop sharing utility for the GNOME desktop environment.

The vulnerabilities referenced below are issues that have originally been reported against Debian source package libvncserver. The vino source package in Debian ships a custom-patched and stripped down variant of libvncserver, thus some of libvncserver's security fixes required porting over.

CVE-2014-6053

The rfbProcessClientNormalMessage function in libvncserver/rfbserver.c in LibVNCServer did not properly handle attempts to send a large amount of ClientCutText data, which allowed remote attackers to cause a denial of service (memory consumption or daemon crash) via a crafted message that was processed by using a single unchecked malloc.

CVE-2018-7225

An issue was discovered in LibVNCServer. rfbProcessClientNormalMessage() in rfbserver.c did not sanitize msg.cct.length, leading to access to uninitialized and potentially sensitive data or possibly unspecified other impact (e.g., an integer overflow) via specially crafted VNC packets.

CVE-2019-15681

LibVNC contained a memory leak (CWE-655) in VNC server code, which allowed an attacker to read stack memory and could be abused for information disclosure. Combined with another vulnerability, it could be used to leak stack memory and bypass ASLR. This attack appeared to be exploitable via network connectivity.

For Debian 8 Jessie, these problems have been fixed in version 3.14.0-2+deb8u1.

We recommend that you upgrade your vino packages.

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'vino' package(s) on Debian 8.");

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

  if(!isnull(res = isdpkgvuln(pkg:"vino", ver:"3.14.0-2+deb8u1", rls:"DEB8"))) {
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
