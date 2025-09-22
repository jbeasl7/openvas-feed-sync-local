# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.72499");
  script_cve_id("CVE-2012-2812", "CVE-2012-2813", "CVE-2012-2814", "CVE-2012-2836", "CVE-2012-2837", "CVE-2012-2840", "CVE-2012-2841");
  script_tag(name:"creation_date", value:"2012-10-22 12:42:32 +0000 (Mon, 22 Oct 2012)");
  script_version("2024-02-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:10 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-2559-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB6");

  script_xref(name:"Advisory-ID", value:"DSA-2559-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2012/DSA-2559-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-2559");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'libexif' package(s) announced via the DSA-2559-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities were found in libexif, a library used to parse EXIF meta-data on camera files.

CVE-2012-2812: A heap-based out-of-bounds array read in the exif_entry_get_value function allows remote attackers to cause a denial of service or possibly obtain potentially sensitive information from process memory via an image with crafted EXIF tags.

CVE-2012-2813: A heap-based out-of-bounds array read in the exif_convert_utf16_to_utf8 function allows remote attackers to cause a denial of service or possibly obtain potentially sensitive information from process memory via an image with crafted EXIF tags.

CVE-2012-2814: A buffer overflow in the exif_entry_format_value function allows remote attackers to cause a denial of service or possibly execute arbitrary code via an image with crafted EXIF tags.

CVE-2012-2836: A heap-based out-of-bounds array read in the exif_data_load_data function allows remote attackers to cause a denial of service or possibly obtain potentially sensitive information from process memory via an image with crafted EXIF tags.

CVE-2012-2837: A divide-by-zero error in the mnote_olympus_entry_get_value function while formatting EXIF maker note tags allows remote attackers to cause a denial of service via an image with crafted EXIF tags.

CVE-2012-2840: An off-by-one error in the exif_convert_utf16_to_utf8 function allows remote attackers to cause a denial of service or possibly execute arbitrary code via an image with crafted EXIF tags.

CVE-2012-2841: An integer underflow in the exif_entry_get_value function can cause a heap overflow and potentially arbitrary code execution while formatting an EXIF tag, if the function is called with a buffer size parameter equal to zero or one.

For the stable distribution (squeeze), these problems have been fixed in version 0.6.19-1+squeeze1.

For the testing distribution (wheezy), these problems have been fixed in version 0.6.20-3.

For the unstable distribution (sid), these problems have been fixed in version 0.6.20-3.

We recommend that you upgrade your libexif packages.");

  script_tag(name:"affected", value:"'libexif' package(s) on Debian 6.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libexif-dev", ver:"0.6.19-1+squeeze1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libexif12", ver:"0.6.19-1+squeeze1", rls:"DEB6"))) {
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
