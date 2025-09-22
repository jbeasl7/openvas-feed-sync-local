# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2021.1850");
  script_cve_id("CVE-2017-11332", "CVE-2017-11358", "CVE-2017-11359", "CVE-2017-15370", "CVE-2017-15371", "CVE-2017-15372", "CVE-2017-15642", "CVE-2019-13590", "CVE-2019-8355", "CVE-2019-8356", "CVE-2019-8357");
  script_tag(name:"creation_date", value:"2021-05-03 06:23:29 +0000 (Mon, 03 May 2021)");
  script_version("2024-02-05T14:36:56+0000");
  script_tag(name:"last_modification", value:"2024-02-05 14:36:56 +0000 (Mon, 05 Feb 2024)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-02-19 18:07:45 +0000 (Tue, 19 Feb 2019)");

  script_name("Huawei EulerOS: Security Advisory for sox (EulerOS-SA-2021-1850)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP3");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2021-1850");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2021-1850");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'sox' package(s) announced via the EulerOS-SA-2021-1850 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"An issue was discovered in libsox.a in SoX 14.4.2. In sox-fmt.h (startread function), there is an integer overflow on the result of integer addition (wraparound to 0) fed into the lsx_calloc macro that wraps malloc. When a NULL pointer is returned, it is used without a prior check that it is a valid pointer, leading to a NULL pointer dereference on lsx_readbuf in formats_i.c.(CVE-2019-13590)

An issue was discovered in SoX 14.4.2. In xmalloc.h, there is an integer overflow on the result of multiplication fed into the lsx_valloc macro that wraps malloc. When the buffer is allocated, it is smaller than expected, leading to a heap-based buffer overflow in channels_start in remix.c.(CVE-2019-8355)

An issue was discovered in SoX 14.4.2. lsx_make_lpf in effect_i_dsp.c allows a NULL pointer dereference.(CVE-2019-8357)

An issue was discovered in SoX 14.4.2. One of the arguments to bitrv2 in fft4g.c is not guarded, such that it can lead to write access outside of the statically declared array, aka a stack-based buffer overflow.(CVE-2019-8356)

In lsx_aiffstartread in aiff.c in Sound eXchange (SoX) 14.4.2, there is a Use-After-Free vulnerability triggered by supplying a malformed AIFF file.(CVE-2017-15642)

The read_samples function in hcom.c in Sound eXchange (SoX) 14.4.2 allows remote attackers to cause a denial of service (invalid memory read and application crash) via a crafted hcom file.(CVE-2017-11358)

The startread function in wav.c in Sound eXchange (SoX) 14.4.2 allows remote attackers to cause a denial of service (divide-by-zero error and application crash) via a crafted wav file.(CVE-2017-11332)

The wavwritehdr function in wav.c in Sound eXchange (SoX) 14.4.2 allows remote attackers to cause a denial of service (divide-by-zero error and application crash) via a crafted snd file, during conversion to a wav file.(CVE-2017-11359)

There is a heap-based buffer overflow in the ImaExpandS function of ima_rw.c in Sound eXchange (SoX) 14.4.2. A Crafted input will lead to a denial of service attack during conversion of an audio file.(CVE-2017-15370)

There is a reachable assertion abort in the function sox_append_comment() in formats.c in Sound eXchange (SoX) 14.4.2. A Crafted input will lead to a denial of service attack during conversion of an audio file.(CVE-2017-15371)

There is a stack-based buffer overflow in the lsx_ms_adpcm_block_expand_i function of adpcm.c in Sound eXchange (SoX) 14.4.2. A Crafted input will lead to a denial of service attack during conversion of an audio file.(CVE-2017-15372)");

  script_tag(name:"affected", value:"'sox' package(s) on Huawei EulerOS V2.0SP3.");

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

  if(!isnull(res = isrpmvuln(pkg:"sox", rpm:"sox~14.4.1~6.h3", rls:"EULEROS-2.0SP3"))) {
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
