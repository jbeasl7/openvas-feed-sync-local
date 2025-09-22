# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2025.1650");
  script_cve_id("CVE-2025-1372", "CVE-2025-1376");
  script_tag(name:"creation_date", value:"2025-06-12 10:55:30 +0000 (Thu, 12 Jun 2025)");
  script_version("2025-06-13T05:40:07+0000");
  script_tag(name:"last_modification", value:"2025-06-13 05:40:07 +0000 (Fri, 13 Jun 2025)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:L");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-02-17 03:15:09 +0000 (Mon, 17 Feb 2025)");

  script_name("Huawei EulerOS: Security Advisory for elfutils (EulerOS-SA-2025-1650)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP11");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2025-1650");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2025-1650");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'elfutils' package(s) announced via the EulerOS-SA-2025-1650 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A vulnerability was found in GNU elfutils 0.192. It has been declared as critical. Affected by this vulnerability is the function dump_data_section/print_string_section of the file readelf.c of the component eu-readelf. The manipulation of the argument z/x leads to buffer overflow. An attack has to be approached locally. The exploit has been disclosed to the public and may be used. The identifier of the patch is 73db9d2021cab9e23fd734b0a76a612d52a6f1db. It is recommended to apply a patch to fix this issue.(CVE-2025-1372)

A vulnerability classified as problematic was found in GNU elfutils 0.192. This vulnerability affects the function elf_strptr in the library /libelf/elf_strptr.c of the component eu-strip. The manipulation leads to denial of service. It is possible to launch the attack on the local host. The complexity of an attack is rather high. The exploitation appears to be difficult. The exploit has been disclosed to the public and may be used. The name of the patch is b16f441cca0a4841050e3215a9f120a6d8aea918. It is recommended to apply a patch to fix this issue.(CVE-2025-1376)");

  script_tag(name:"affected", value:"'elfutils' package(s) on Huawei EulerOS V2.0SP11.");

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

if(release == "EULEROS-2.0SP11") {

  if(!isnull(res = isrpmvuln(pkg:"elfutils", rpm:"elfutils~0.185~5.h11.eulerosv2r11", rls:"EULEROS-2.0SP11"))) {
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
