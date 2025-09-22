# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2019.2226");
  script_cve_id("CVE-2016-0740", "CVE-2016-0775", "CVE-2016-2533", "CVE-2016-9189");
  script_tag(name:"creation_date", value:"2020-01-23 12:41:31 +0000 (Thu, 23 Jan 2020)");
  script_version("2024-02-05T14:36:56+0000");
  script_tag(name:"last_modification", value:"2024-02-05 14:36:56 +0000 (Mon, 05 Feb 2024)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-11-04 16:59:44 +0000 (Fri, 04 Nov 2016)");

  script_name("Huawei EulerOS: Security Advisory for python-pillow (EulerOS-SA-2019-2226)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP5");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2019-2226");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2019-2226");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'python-pillow' package(s) announced via the EulerOS-SA-2019-2226 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Buffer overflow in the ImagingPcdDecode function in PcdDecode.c in Pillow before 3.1.1 and Python Imaging Library (PIL) 1.1.7 and earlier allows remote attackers to cause a denial of service (crash) via a crafted PhotoCD file.(CVE-2016-2533)

Pillow before 3.3.2 allows context-dependent attackers to obtain sensitive information by using the 'crafted image file' approach, related to an 'Integer Overflow' issue affecting the Image.core.map_buffer in map.c component.(CVE-2016-9189)

Buffer overflow in the ImagingFliDecode function in libImaging/FliDecode.c in Pillow before 3.1.1 allows remote attackers to cause a denial of service (crash) via a crafted FLI file.(CVE-2016-0775)

Buffer overflow in the ImagingLibTiffDecode function in libImaging/TiffDecode.c in Pillow before 3.1.1 allows remote attackers to overwrite memory via a crafted TIFF file.(CVE-2016-0740)");

  script_tag(name:"affected", value:"'python-pillow' package(s) on Huawei EulerOS V2.0SP5.");

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

  if(!isnull(res = isrpmvuln(pkg:"python-pillow", rpm:"python-pillow~2.0.0~19.h2.gitd1c6db8.eulerosv2r7", rls:"EULEROS-2.0SP5"))) {
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
