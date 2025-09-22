# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2019.2208");
  script_cve_id("CVE-2014-9496", "CVE-2014-9756", "CVE-2017-14245", "CVE-2017-14246", "CVE-2017-14634", "CVE-2017-16942", "CVE-2017-17456", "CVE-2017-17457", "CVE-2017-6892", "CVE-2017-7585", "CVE-2017-7586", "CVE-2017-7741", "CVE-2017-7742", "CVE-2017-8361", "CVE-2017-8362", "CVE-2017-8363", "CVE-2017-8365");
  script_tag(name:"creation_date", value:"2020-01-23 12:39:01 +0000 (Thu, 23 Jan 2020)");
  script_version("2024-02-05T14:36:56+0000");
  script_tag(name:"last_modification", value:"2024-02-05 14:36:56 +0000 (Mon, 05 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-04-30 19:59:00 +0000 (Sun, 30 Apr 2017)");

  script_name("Huawei EulerOS: Security Advisory for libsndfile (EulerOS-SA-2019-2208)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP5");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2019-2208");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2019-2208");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'libsndfile' package(s) announced via the EulerOS-SA-2019-2208 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"In libsndfile version 1.0.28, an error in the 'aiff_read_chanmap()' function (aiff.c) can be exploited to cause an out-of-bounds read memory access via a specially crafted AIFF file.(CVE-2017-6892)

The sd2_parse_rsrc_fork function in sd2.c in libsndfile allows attackers to have unspecified impact via vectors related to a (1) map offset or (2) rsrc marker, which triggers an out-of-bounds read.(CVE-2014-9496)

The flac_buffer_copy function in flac.c in libsndfile 1.0.28 allows remote attackers to cause a denial of service (buffer overflow and application crash) or possibly have unspecified other impact via a crafted audio file.(CVE-2017-8361)

In libsndfile before 1.0.28, an error in the 'flac_buffer_copy()' function (flac.c) can be exploited to cause a segmentation violation (with write memory access) via a specially crafted FLAC file during a resample attempt, a similar issue to CVE-2017-7585.(CVE-2017-7741)

In libsndfile before 1.0.28, an error in the 'flac_buffer_copy()' function (flac.c) can be exploited to cause a segmentation violation (with read memory access) via a specially crafted FLAC file during a resample attempt, a similar issue to CVE-2017-7585.(CVE-2017-7742)

In libsndfile before 1.0.28, an error in the 'flac_buffer_copy()' function (flac.c) can be exploited to cause a stack-based buffer overflow via a specially crafted FLAC file.(CVE-2017-7585)

An out of bounds read in the function d2ulaw_array() in ulaw.c of libsndfile 1.0.28 may lead to a remote DoS attack or information disclosure, related to mishandling of the NAN and INFINITY floating-point values.(CVE-2017-14246)

An out of bounds read in the function d2alaw_array() in alaw.c of libsndfile 1.0.28 may lead to a remote DoS attack or information disclosure, related to mishandling of the NAN and INFINITY floating-point values.(CVE-2017-14245)

The function d2ulaw_array() in ulaw.c of libsndfile 1.0.29pre1 may lead to a remote DoS attack (SEGV on unknown address 0x000000000000), a different vulnerability than CVE-2017-14246.(CVE-2017-17457)

The function d2alaw_array() in alaw.c of libsndfile 1.0.29pre1 may lead to a remote DoS attack (SEGV on unknown address 0x000000000000), a different vulnerability than CVE-2017-14245.(CVE-2017-17456)

In libsndfile 1.0.28, a divide-by-zero error exists in the function double64_init() in double64.c, which may lead to DoS when playing a crafted audio file.(CVE-2017-14634)

The psf_fwrite function in file_io.c in libsndfile allows attackers to cause a denial of service (divide-by-zero error and application crash) via unspecified vectors related to the headindex variable.(CVE-2014-9756)

In libsndfile before 1.0.28, an error in the 'header_read()' function (common.c) when handling ID3 tags can be exploited to cause a stack-based buffer overflow via a specially crafted FLAC file.(CVE-2017-7586)

The flac_buffer_copy function in flac.c in libsndfile 1.0.28 allows ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'libsndfile' package(s) on Huawei EulerOS V2.0SP5.");

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

if(release == "EULEROS-2.0SP5") {

  if(!isnull(res = isrpmvuln(pkg:"libsndfile", rpm:"libsndfile~1.0.25~10.h9.eulerosv2r7", rls:"EULEROS-2.0SP5"))) {
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
