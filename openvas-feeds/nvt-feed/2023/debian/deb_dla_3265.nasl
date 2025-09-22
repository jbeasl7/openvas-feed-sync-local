# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.893265");
  script_cve_id("CVE-2017-11591", "CVE-2017-14859", "CVE-2017-14862", "CVE-2017-14864", "CVE-2017-17669", "CVE-2017-18005", "CVE-2018-17581", "CVE-2018-19107", "CVE-2018-19108", "CVE-2018-19535", "CVE-2018-20097", "CVE-2018-8976", "CVE-2019-13110", "CVE-2019-13112", "CVE-2019-13114", "CVE-2019-13504", "CVE-2019-14369", "CVE-2019-14370", "CVE-2019-17402", "CVE-2020-18771", "CVE-2021-29458", "CVE-2021-32815", "CVE-2021-34334", "CVE-2021-37620", "CVE-2021-37621", "CVE-2021-37622");
  script_tag(name:"creation_date", value:"2023-01-11 02:00:22 +0000 (Wed, 11 Jan 2023)");
  script_version("2024-02-02T05:06:10+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:10 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-08-30 16:12:59 +0000 (Mon, 30 Aug 2021)");

  script_name("Debian: Security Advisory (DLA-3265-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB10");

  script_xref(name:"Advisory-ID", value:"DLA-3265-1");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2023/DLA-3265-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/exiv2");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'exiv2' package(s) announced via the DLA-3265-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update fixes a number of memory access violations and other input validation failures that can be triggered by passing specially crafted files to exiv2.

CVE-2017-11591

There is a Floating point exception in the Exiv2::ValueType function that will lead to a remote denial of service attack via crafted input.

CVE-2017-14859

An Invalid memory address dereference was discovered in Exiv2::StringValueBase::read in value.cpp. The vulnerability causes a segmentation fault and application crash, which leads to denial of service.

CVE-2017-14862

An Invalid memory address dereference was discovered in Exiv2::DataValue::read in value.cpp. The vulnerability causes a segmentation fault and application crash, which leads to denial of service.

CVE-2017-14864

An Invalid memory address dereference was discovered in Exiv2::getULong in types.cpp. The vulnerability causes a segmentation fault and application crash, which leads to denial of service.

CVE-2017-17669

There is a heap-based buffer over-read in the Exiv2::Internal::PngChunk::keyTXTChunk function of pngchunk_int.cpp. A crafted PNG file will lead to a remote denial of service attack.

CVE-2017-18005

Exiv2 has a Null Pointer Dereference in the Exiv2::DataValue::toLong function in value.cpp, related to crafted metadata in a TIFF file.

CVE-2018-8976

jpgimage.cpp allows remote attackers to cause a denial of service (image.cpp Exiv2::Internal::stringFormat out-of-bounds read) via a crafted file.

CVE-2018-17581

CiffDirectory::readDirectory() at crwimage_int.cpp has excessive stack consumption due to a recursive function, leading to Denial of service.

CVE-2018-19107

Exiv2::IptcParser::decode in iptc.cpp (called from psdimage.cpp in the PSD image reader) may suffer from a denial of service (heap-based buffer over-read) caused by an integer overflow via a crafted PSD image file.

CVE-2018-19108

Exiv2::PsdImage::readMetadata in psdimage.cpp in the PSD image reader may suffer from a denial of service (infinite loop) caused by an integer overflow via a crafted PSD image file.

CVE-2018-19535

PngChunk::readRawProfile in pngchunk_int.cpp may cause a denial of service (application crash due to a heap-based buffer over-read) via a crafted PNG file.

CVE-2018-20097

There is a SEGV in Exiv2::Internal::TiffParserWorker::findPrimaryGroups of tiffimage_int.cpp. A crafted input will lead to a remote denial of service attack.

CVE-2019-13110

A CiffDirectory::readDirectory integer overflow and out-of-bounds read allows an attacker to cause a denial of service (SIGSEGV) via a crafted CRW image file.

CVE-2019-13112

A PngChunk::parseChunkContent uncontrolled memory allocation allows an attacker to cause a denial of service (crash due to an std::bad_alloc exception) via a crafted PNG image file.

CVE-2019-13114

http.c allows a malicious http server to cause a denial of service (crash due to a NULL pointer dereference) by returning a ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'exiv2' package(s) on Debian 10.");

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

if(release == "DEB10") {

  if(!isnull(res = isdpkgvuln(pkg:"exiv2", ver:"0.25-4+deb10u4", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libexiv2-14", ver:"0.25-4+deb10u4", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libexiv2-dev", ver:"0.25-4+deb10u4", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libexiv2-doc", ver:"0.25-4+deb10u4", rls:"DEB10"))) {
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
