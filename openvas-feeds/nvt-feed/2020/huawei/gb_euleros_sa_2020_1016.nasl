# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2020.1016");
  script_cve_id("CVE-2017-14634", "CVE-2017-17456", "CVE-2017-17457", "CVE-2018-19432", "CVE-2018-19661", "CVE-2018-19758");
  script_tag(name:"creation_date", value:"2020-01-23 13:16:24 +0000 (Thu, 23 Jan 2020)");
  script_version("2024-02-05T14:36:56+0000");
  script_tag(name:"last_modification", value:"2024-02-05 14:36:56 +0000 (Mon, 05 Feb 2024)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-12-26 17:05:10 +0000 (Wed, 26 Dec 2018)");

  script_name("Huawei EulerOS: Security Advisory for libsndfile (EulerOS-SA-2020-1016)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP8");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2020-1016");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2020-1016");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'libsndfile' package(s) announced via the EulerOS-SA-2020-1016 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The function d2ulaw_array() in ulaw.c of libsndfile 1.0.29pre1 may lead to a remote DoS attack (SEGV on unknown address 0x000000000000), a different vulnerability than CVE-2017-14246.(CVE-2017-17457)

The function d2alaw_array() in alaw.c of libsndfile 1.0.29pre1 may lead to a remote DoS attack (SEGV on unknown address 0x000000000000), a different vulnerability than CVE-2017-14245.(CVE-2017-17456)

In libsndfile 1.0.28, a divide-by-zero error exists in the function double64_init() in double64.c, which may lead to DoS when playing a crafted audio file.(CVE-2017-14634)

There is a heap-based buffer over-read at wav.c in wav_write_header in libsndfile 1.0.28 that will cause a denial of service.(CVE-2018-19758)

An issue was discovered in libsndfile 1.0.28. There is a buffer over-read in the function i2ulaw_array in ulaw.c that will lead to a denial of service.(CVE-2018-19661)

An issue was discovered in libsndfile 1.0.28. There is a NULL pointer dereference in the function sf_write_int in sndfile.c, which will lead to a denial of service.(CVE-2018-19432)");

  script_tag(name:"affected", value:"'libsndfile' package(s) on Huawei EulerOS V2.0SP8.");

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

if(release == "EULEROS-2.0SP8") {

  if(!isnull(res = isrpmvuln(pkg:"libsndfile", rpm:"libsndfile~1.0.28~9.h5.eulerosv2r8", rls:"EULEROS-2.0SP8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsndfile-devel", rpm:"libsndfile-devel~1.0.28~9.h5.eulerosv2r8", rls:"EULEROS-2.0SP8"))) {
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
