# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.71154");
  script_cve_id("CVE-2010-4540", "CVE-2010-4541", "CVE-2010-4542", "CVE-2010-4543", "CVE-2011-1782", "CVE-2011-2896");
  script_tag(name:"creation_date", value:"2012-03-12 15:33:30 +0000 (Mon, 12 Mar 2012)");
  script_version("2024-02-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:10 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-2426-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB6");

  script_xref(name:"Advisory-ID", value:"DSA-2426-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2012/DSA-2426-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-2426");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'gimp' package(s) announced via the DSA-2426-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been identified in GIMP, the GNU Image Manipulation Program.

CVE-2010-4540

Stack-based buffer overflow in the load_preset_response function in plug-ins/lighting/lighting-ui.c in the LIGHTING EFFECTS & LIGHT plugin allows user-assisted remote attackers to cause a denial of service (application crash) or possibly execute arbitrary code via a long Position field in a plugin configuration file.

CVE-2010-4541

Stack-based buffer overflow in the loadit function in plug-ins/common/sphere-designer.c in the SPHERE DESIGNER plugin allows user-assisted remote attackers to cause a denial of service (application crash) or possibly execute arbitrary code via a long Number of lights field in a plugin configuration file.

CVE-2010-4542

Stack-based buffer overflow in the gfig_read_parameter_gimp_rgb function in the GFIG plugin allows user-assisted remote attackers to cause a denial of service (application crash) or possibly execute arbitrary code via a long Foreground field in a plugin configuration file.

CVE-2010-4543

Heap-based buffer overflow in the read_channel_data function in file-psp.c in the Paint Shop Pro (PSP) plugin allows remote attackers to cause a denial of service (application crash) or possibly execute arbitrary code via a PSP_COMP_RLE (aka RLE compression) image file that begins a long run count at the end of the image.

CVE-2011-1782

The correction for CVE-2010-4543 was incomplete.

CVE-2011-2896

The LZW decompressor in the LZWReadByte function in plug-ins/common/file-gif-load.c does not properly handle code words that are absent from the decompression table when encountered, which allows remote attackers to trigger an infinite loop or a heap-based buffer overflow, and possibly execute arbitrary code, via a crafted compressed stream.

For the stable distribution (squeeze), these problems have been fixed in version 2.6.10-1+squeeze3.

For the testing distribution (wheezy) and the unstable distribution (sid), these problems have been fixed in version 2.6.11-5.

We recommend that you upgrade your gimp packages.");

  script_tag(name:"affected", value:"'gimp' package(s) on Debian 6.");

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

if(release == "DEB6") {

  if(!isnull(res = isdpkgvuln(pkg:"gimp", ver:"2.6.10-1+squeeze3", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"gimp-data", ver:"2.6.10-1+squeeze3", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"gimp-dbg", ver:"2.6.10-1+squeeze3", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libgimp2.0", ver:"2.6.10-1+squeeze3", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libgimp2.0-dev", ver:"2.6.10-1+squeeze3", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libgimp2.0-doc", ver:"2.6.10-1+squeeze3", rls:"DEB6"))) {
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
