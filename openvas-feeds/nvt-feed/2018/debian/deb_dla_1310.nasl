# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.891310");
  script_cve_id("CVE-2017-18233", "CVE-2017-18234", "CVE-2017-18236", "CVE-2017-18238", "CVE-2018-7728", "CVE-2018-7730");
  script_tag(name:"creation_date", value:"2018-03-26 22:00:00 +0000 (Mon, 26 Mar 2018)");
  script_version("2024-02-02T05:06:06+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:06 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-04-05 16:54:06 +0000 (Thu, 05 Apr 2018)");

  script_name("Debian: Security Advisory (DLA-1310-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB7");

  script_xref(name:"Advisory-ID", value:"DLA-1310-1");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2018/DLA-1310-1");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'exempi' package(s) announced via the DLA-1310-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Various issues were discovered in exempi, a library to parse XMP metadata that may cause a denial-of-service or may have other unspecified impact via crafted files.

CVE-2017-18233

An Integer overflow in the Chunk class in RIFF.cpp allows remote attackers to cause a denial of service (infinite loop) via crafted XMP data in an .avi file.

CVE-2017-18234

An issue was discovered that allows remote attackers to cause a denial of service (invalid memcpy with resultant use-after-free) or possibly have unspecified other impact via a .pdf file containing JPEG data.

CVE-2017-18236

The ASF_Support::ReadHeaderObject function in ASF_Support.cpp allows remote attackers to cause a denial of service (infinite loop) via a crafted .asf file.

CVE-2017-18238

The TradQT_Manager::ParseCachedBoxes function in QuickTime_Support.cpp allows remote attackers to cause a denial of service (infinite loop) via crafted XMP data in a .qt file.

CVE-2018-7728

TIFF_Handler.cpp mishandles a case of a zero length, leading to a heap-based buffer over-read in the MD5Update() function in MD5.cpp.

CVE-2018-7730

A certain case of a 0xffffffff length is mishandled in PSIR_FileWriter.cpp, leading to a heap-based buffer over-read in the PSD_MetaHandler::CacheFileData() function.

For Debian 7 Wheezy, these problems have been fixed in version 2.2.0-1+deb7u1.

We recommend that you upgrade your exempi packages.

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'exempi' package(s) on Debian 7.");

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

if(release == "DEB7") {

  if(!isnull(res = isdpkgvuln(pkg:"libexempi-dev", ver:"2.2.0-1+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libexempi3", ver:"2.2.0-1+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libexempi3-dbg", ver:"2.2.0-1+deb7u1", rls:"DEB7"))) {
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
