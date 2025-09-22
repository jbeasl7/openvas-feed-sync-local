# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2019.2639");
  script_cve_id("CVE-2013-6887", "CVE-2014-0158", "CVE-2016-10505", "CVE-2016-7445", "CVE-2017-14040", "CVE-2017-14041", "CVE-2017-17479");
  script_tag(name:"creation_date", value:"2020-01-23 13:10:42 +0000 (Thu, 23 Jan 2020)");
  script_version("2024-02-05T14:36:56+0000");
  script_tag(name:"last_modification", value:"2024-02-05 14:36:56 +0000 (Mon, 05 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-12-20 20:15:15 +0000 (Wed, 20 Dec 2017)");

  script_name("Huawei EulerOS: Security Advisory for openjpeg (EulerOS-SA-2019-2639)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP3");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2019-2639");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2019-2639");
  script_xref(name:"URL", value:"http://openwall.com/lists/oss-security/2013/12/04/6");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'openjpeg' package(s) announced via the EulerOS-SA-2019-2639 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A stack-based buffer overflow was discovered in the pgxtoimage function in bin/jp2/convert.c in OpenJPEG 2.2.0. The vulnerability causes an out-of-bounds write, which may lead to remote denial of service or possibly remote code execution.(CVE-2017-14041)

An invalid write access was discovered in bin/jp2/convert.c in OpenJPEG 2.2.0, triggering a crash in the tgatoimage function. The vulnerability may lead to remote denial of service or possibly unspecified other impact.(CVE-2017-14040)

convert.c in OpenJPEG before 2.1.2 allows remote attackers to cause a denial of service (NULL pointer dereference and application crash) via vectors involving the variable s.(CVE-2016-7445)

Heap-based buffer overflow in the JPEG2000 image tile decoder in OpenJPEG before 1.5.2 allows remote attackers to cause a denial of service (application crash) or possibly have unspecified other impact via a crafted file because of incorrect j2k_decode, j2k_read_eoc, and tcd_decode_tile interaction, a related issue to CVE-2013-6045. NOTE: this is not a duplicate of CVE-2013-1447, because the scope of CVE-2013-1447 was specifically defined in [link moved to references] as only 'null pointer dereferences, division by zero, and anything that would just fit as DoS.'(CVE-2014-0158)

In OpenJPEG 2.3.0, a stack-based buffer overflow was discovered in the pgxtoimage function in jpwl/convert.c. The vulnerability causes an out-of-bounds write, which may lead to remote denial of service or possibly remote code execution.(CVE-2017-17479)

NULL pointer dereference vulnerabilities in the imagetopnm function in convert.c, sycc444_to_rgb function in color.c, color_esycc_to_rgb function in color.c, and sycc422_to_rgb function in color.c in OpenJPEG before 2.2.0 allow remote attackers to cause a denial of service (application crash) via crafted j2k files.(CVE-2016-10505)

OpenJPEG 1.5.1 allows remote attackers to cause a denial of service via unspecified vectors that trigger NULL pointer dereferences, division-by-zero, and other errors.(CVE-2013-6887)");

  script_tag(name:"affected", value:"'openjpeg' package(s) on Huawei EulerOS V2.0SP3.");

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

  if(!isnull(res = isrpmvuln(pkg:"openjpeg-libs", rpm:"openjpeg-libs~1.5.1~16.h2", rls:"EULEROS-2.0SP3"))) {
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
