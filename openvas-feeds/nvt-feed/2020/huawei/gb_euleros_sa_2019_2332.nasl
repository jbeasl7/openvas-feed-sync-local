# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2019.2332");
  script_cve_id("CVE-2016-9396", "CVE-2017-1000050", "CVE-2018-19540", "CVE-2018-19541");
  script_tag(name:"creation_date", value:"2020-01-23 12:47:23 +0000 (Thu, 23 Jan 2020)");
  script_version("2024-02-05T14:36:56+0000");
  script_tag(name:"last_modification", value:"2024-02-05 14:36:56 +0000 (Mon, 05 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-12-07 18:49:31 +0000 (Fri, 07 Dec 2018)");

  script_name("Huawei EulerOS: Security Advisory for jasper (EulerOS-SA-2019-2332)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROSVIRTARM64\-3\.0\.3\.0");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2019-2332");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2019-2332");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'jasper' package(s) announced via the EulerOS-SA-2019-2332 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"JasPer 2.0.12 is vulnerable to a NULL pointer exception in the function jp2_encode which failed to check to see if the image contained at least one component resulting in a denial-of-service.(CVE-2017-1000050)

The JPC_NOMINALGAIN function in jpc/jpc_t1cod.c in JasPer through 2.0.12 allows remote attackers to cause a denial of service (JPC_COX_RFT assertion failure) via unspecified vectors.(CVE-2016-9396)

An issue was discovered in JasPer 2.0.14. There is a heap-based buffer over-read of size 8 in the function jas_image_depalettize in libjasper/base/jas_image.c.(CVE-2018-19541)

An issue was discovered in JasPer 2.0.14. There is a heap-based buffer overflow of size 1 in the function jas_icctxtdesc_input in libjasper/base/jas_icc.c.(CVE-2018-19540)");

  script_tag(name:"affected", value:"'jasper' package(s) on Huawei EulerOS Virtualization for ARM 64 3.0.3.0.");

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

if(release == "EULEROSVIRTARM64-3.0.3.0") {

  if(!isnull(res = isrpmvuln(pkg:"jasper-libs", rpm:"jasper-libs~2.0.14~7.h1.eulerosv2r8", rls:"EULEROSVIRTARM64-3.0.3.0"))) {
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
