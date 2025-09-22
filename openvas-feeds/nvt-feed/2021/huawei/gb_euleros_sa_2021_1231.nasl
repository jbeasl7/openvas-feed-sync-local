# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2021.1231");
  script_cve_id("CVE-2017-11332", "CVE-2017-11358", "CVE-2017-11359", "CVE-2017-15370", "CVE-2017-15371", "CVE-2017-15372", "CVE-2017-15642");
  script_tag(name:"creation_date", value:"2021-02-05 15:04:32 +0000 (Fri, 05 Feb 2021)");
  script_version("2024-02-05T14:36:56+0000");
  script_tag(name:"last_modification", value:"2024-02-05 14:36:56 +0000 (Mon, 05 Feb 2024)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-10-31 22:09:07 +0000 (Tue, 31 Oct 2017)");

  script_name("Huawei EulerOS: Security Advisory for sox (EulerOS-SA-2021-1231)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP5");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2021-1231");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2021-1231");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'sox' package(s) announced via the EulerOS-SA-2021-1231 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The startread function in wav.c in Sound eXchange (SoX) 14.4.2 allows remote attackers to cause a denial of service (divide-by-zero error and application crash) via a crafted wav file.(CVE-2017-11332)

The read_samples function in hcom.c in Sound eXchange (SoX) 14.4.2 allows remote attackers to cause a denial of service (invalid memory read and application crash) via a crafted hcom file.(CVE-2017-11358)

The wavwritehdr function in wav.c in Sound eXchange (SoX) 14.4.2 allows remote attackers to cause a denial of service (divide-by-zero error and application crash) via a crafted snd file, during conversion to a wav file.(CVE-2017-11359)

There is a heap-based buffer overflow in the ImaExpandS function of ima_rw.c in Sound eXchange (SoX) 14.4.2. A Crafted input will lead to a denial of service attack during conversion of an audio file.(CVE-2017-15370)

There is a reachable assertion abort in the function sox_append_comment() in formats.c in Sound eXchange (SoX) 14.4.2. A Crafted input will lead to a denial of service attack during conversion of an audio file.(CVE-2017-15371)

There is a stack-based buffer overflow in the lsx_ms_adpcm_block_expand_i function of adpcm.c in Sound eXchange (SoX) 14.4.2. A Crafted input will lead to a denial of service attack during conversion of an audio file.(CVE-2017-15372)

In lsx_aiffstartread in aiff.c in Sound eXchange (SoX) 14.4.2, there is a Use-After-Free vulnerability triggered by supplying a malformed AIFF file.(CVE-2017-15642)");

  script_tag(name:"affected", value:"'sox' package(s) on Huawei EulerOS V2.0SP5.");

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

  if(!isnull(res = isrpmvuln(pkg:"sox", rpm:"sox~14.4.1~6.h4.eulerosv2r7", rls:"EULEROS-2.0SP5"))) {
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
