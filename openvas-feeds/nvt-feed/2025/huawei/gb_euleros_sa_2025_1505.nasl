# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2025.1505");
  script_cve_id("CVE-2025-1352", "CVE-2025-1377");
  script_tag(name:"creation_date", value:"2025-05-13 04:28:55 +0000 (Tue, 13 May 2025)");
  script_version("2025-05-13T05:41:39+0000");
  script_tag(name:"last_modification", value:"2025-05-13 05:41:39 +0000 (Tue, 13 May 2025)");
  script_tag(name:"cvss_base", value:"5.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:L");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-02-16 15:15:09 +0000 (Sun, 16 Feb 2025)");

  script_name("Huawei EulerOS: Security Advisory for elfutils (EulerOS-SA-2025-1505)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP10");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2025-1505");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2025-1505");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'elfutils' package(s) announced via the EulerOS-SA-2025-1505 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A vulnerability, which was classified as problematic, has been found in GNU elfutils 0.192. This issue affects the function gelf_getsymshndx of the file strip.c of the component eu-strip. The manipulation leads to denial of service. The attack needs to be approached locally. The exploit has been disclosed to the public and may be used. The identifier of the patch is fbf1df9ca286de3323ae541973b08449f8d03aba. It is recommended to apply a patch to fix this issue.(CVE-2025-1377)

A vulnerability has been found in GNU elfutils 0.192 and classified as critical. This vulnerability affects the function __libdw_thread_tail in the library libdw_alloc.c of the component eu-readelf. The manipulation of the argument w leads to memory corruption. The attack can be initiated remotely. The complexity of an attack is rather high. The exploitation appears to be difficult. The exploit has been disclosed to the public and may be used. The name of the patch is 2636426a091bd6c6f7f02e49ab20d4cdc6bfc753. It is recommended to apply a patch to fix this issue.(CVE-2025-1352)");

  script_tag(name:"affected", value:"'elfutils' package(s) on Huawei EulerOS V2.0SP10.");

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

if(release == "EULEROS-2.0SP10") {

  if(!isnull(res = isrpmvuln(pkg:"elfutils", rpm:"elfutils~0.180~1.h7.eulerosv2r10", rls:"EULEROS-2.0SP10"))) {
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
