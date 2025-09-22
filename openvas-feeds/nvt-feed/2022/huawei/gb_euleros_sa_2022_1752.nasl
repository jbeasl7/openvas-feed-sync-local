# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2022.1752");
  script_cve_id("CVE-2019-20792", "CVE-2020-26570", "CVE-2020-26571", "CVE-2020-26572");
  script_tag(name:"creation_date", value:"2022-05-25 04:17:28 +0000 (Wed, 25 May 2022)");
  script_version("2024-02-05T14:36:57+0000");
  script_tag(name:"last_modification", value:"2024-02-05 14:36:57 +0000 (Mon, 05 Feb 2024)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-05-26 16:51:15 +0000 (Tue, 26 May 2020)");

  script_name("Huawei EulerOS: Security Advisory for opensc (EulerOS-SA-2022-1752)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP3");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2022-1752");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2022-1752");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'opensc' package(s) announced via the EulerOS-SA-2022-1752 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A use-after-free vulnerability was discovered in OpenSC while disconnecting a smart card. This flaw allows a physical attacker to exploit this vulnerability by inserting and removing a malicious smart card, handled by the coolkey driver, that could potentially execute code on the target system, with privileges that depend on the particular configuration and system that makes use of the OpenSC library.(CVE-2019-20792)

The gemsafe GPK smart card software driver in OpenSC before 0.21.0-rc1 has a stack-based buffer overflow in sc_pkcs15emu_gemsafeGPK_init.(CVE-2020-26571)

The TCOS smart card software driver in OpenSC before 0.21.0-rc1 has a stack-based buffer overflow in tcos_decipher.(CVE-2020-26572)

The Oberthur smart card software driver in OpenSC before 0.21.0-rc1 has a heap-based buffer overflow in sc_oberthur_read_file.(CVE-2020-26570)");

  script_tag(name:"affected", value:"'opensc' package(s) on Huawei EulerOS V2.0SP3.");

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

  if(!isnull(res = isrpmvuln(pkg:"opensc", rpm:"opensc~0.16.0~5.20170227git777e2a3.h4", rls:"EULEROS-2.0SP3"))) {
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
