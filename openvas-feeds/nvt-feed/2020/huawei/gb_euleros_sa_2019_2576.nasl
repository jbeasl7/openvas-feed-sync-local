# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2019.2576");
  script_cve_id("CVE-2017-11591", "CVE-2017-11683", "CVE-2017-14859", "CVE-2017-14862", "CVE-2017-14864", "CVE-2017-17669", "CVE-2017-18005", "CVE-2017-9239", "CVE-2018-10958", "CVE-2018-10998", "CVE-2018-10999", "CVE-2018-17581", "CVE-2018-19107", "CVE-2018-19108", "CVE-2018-19535", "CVE-2018-20097", "CVE-2019-13112", "CVE-2019-13113");
  script_tag(name:"creation_date", value:"2020-01-23 13:06:56 +0000 (Thu, 23 Jan 2020)");
  script_version("2024-02-05T14:36:56+0000");
  script_tag(name:"last_modification", value:"2024-02-05 14:36:56 +0000 (Mon, 05 Feb 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-07-28 18:59:44 +0000 (Fri, 28 Jul 2017)");

  script_name("Huawei EulerOS: Security Advisory for exiv2 (EulerOS-SA-2019-2576)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP3");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2019-2576");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2019-2576");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'exiv2' package(s) announced via the EulerOS-SA-2019-2576 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A PngChunk::parseChunkContent uncontrolled memory allocation in Exiv2 through 0.27.1 allows an attacker to cause a denial of service (crash due to an std::bad_alloc exception) via a crafted PNG image file.(CVE-2019-13112)

An Invalid memory address dereference was discovered in Exiv2::DataValue::read in value.cpp in Exiv2 0.26. The vulnerability causes a segmentation fault and application crash, which leads to denial of service.(CVE-2017-14862)

An Invalid memory address dereference was discovered in Exiv2::getULong in types.cpp in Exiv2 0.26. The vulnerability causes a segmentation fault and application crash, which leads to denial of service.(CVE-2017-14864)

An Invalid memory address dereference was discovered in Exiv2::StringValueBase::read in value.cpp in Exiv2 0.26. The vulnerability causes a segmentation fault and application crash, which leads to denial of service.(CVE-2017-14859)

An issue was discovered in Exiv2 0.26. readMetadata in jp2image.cpp allows remote attackers to cause a denial of service (SIGABRT) by triggering an incorrect Safe::add call.(CVE-2018-10998)

An issue was discovered in Exiv2 0.26. The Exiv2::Internal::PngChunk::parseTXTChunk function has a heap-based buffer over-read.(CVE-2018-10999)

An issue was discovered in Exiv2 0.26. When the data structure of the structure ifd is incorrect, the program assigns pValue_ to 0x0, and the value of pValue() is 0x0. TiffImageEntry::doWriteImage will use the value of pValue() to cause a segmentation fault. To exploit this vulnerability, someone must open a crafted tiff file.(CVE-2017-9239)

CiffDirectory::readDirectory() at crwimage_int.cpp in Exiv2 0.26 has excessive stack consumption due to a recursive function, leading to Denial of service.(CVE-2018-17581)

Exiv2 0.26 has a Null Pointer Dereference in the Exiv2::DataValue::toLong function in value.cpp, related to crafted metadata in a TIFF file.(CVE-2017-18005)

Exiv2 through 0.27.1 allows an attacker to cause a denial of service (crash due to assertion failure) via an invalid data location in a CRW image file.(CVE-2019-13113)

In Exiv2 0.26 and previous versions, PngChunk::readRawProfile in pngchunk_int.cpp may cause a denial of service (application crash due to a heap-based buffer over-read) via a crafted PNG file.(CVE-2018-19535)

In Exiv2 0.26, Exiv2::IptcParser::decode in iptc.cpp (called from psdimage.cpp in the PSD image reader) may suffer from a denial of service (heap-based buffer over-read) caused by an integer overflow via a crafted PSD image file.(CVE-2018-19107)

In Exiv2 0.26, Exiv2::PsdImage::readMetadata in psdimage.cpp in the PSD image reader may suffer from a denial of service (infinite loop) caused by an integer overflow via a crafted PSD image file.(CVE-2018-19108)

In types.cpp in Exiv2 0.26, a large size value may lead to a SIGABRT during an attempt at memory allocation for an Exiv2::Internal::PngChunk::zlibUncompress ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'exiv2' package(s) on Huawei EulerOS V2.0SP3.");

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

if(release == "EULEROS-2.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"exiv2-libs", rpm:"exiv2-libs~0.23~6.h7", rls:"EULEROS-2.0SP3"))) {
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
