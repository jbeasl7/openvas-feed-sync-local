# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2023.2098");
  script_cve_id("CVE-2022-41973", "CVE-2022-41974");
  script_tag(name:"creation_date", value:"2023-06-07 04:14:30 +0000 (Wed, 07 Jun 2023)");
  script_version("2024-02-05T14:36:57+0000");
  script_tag(name:"last_modification", value:"2024-02-05 14:36:57 +0000 (Mon, 05 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-10-31 19:47:24 +0000 (Mon, 31 Oct 2022)");

  script_name("Huawei EulerOS: Security Advisory for multipath-tools (EulerOS-SA-2023-2098)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROSVIRT\-2\.11\.0");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2023-2098");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2023-2098");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'multipath-tools' package(s) announced via the EulerOS-SA-2023-2098 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"multipath-tools 0.7.7 through 0.9.x before 0.9.2 allows local users to obtain root access, as exploited in conjunction with CVE-2022-41974. Local users able to access /dev/shm can change symlinks in multipathd due to incorrect symlink handling, which could lead to controlled file writes outside of the /dev/shm directory. This could be used indirectly for local privilege escalation to root.(CVE-2022-41973)

multipath-tools 0.7.0 through 0.9.x before 0.9.2 allows local users to obtain root access, as exploited alone or in conjunction with CVE-2022-41973. Local users able to write to UNIX domain sockets can bypass access controls and manipulate the multipath setup. This can lead to local privilege escalation to root. This occurs because an attacker can repeat a keyword, which is mishandled because arithmetic ADD is used instead of bitwise OR.(CVE-2022-41974)");

  script_tag(name:"affected", value:"'multipath-tools' package(s) on Huawei EulerOS Virtualization release 2.11.0.");

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

if(release == "EULEROSVIRT-2.11.0") {

  if(!isnull(res = isrpmvuln(pkg:"kpartx", rpm:"kpartx~0.8.7~2.h6.eulerosv2r11", rls:"EULEROSVIRT-2.11.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"multipath-tools", rpm:"multipath-tools~0.8.7~2.h6.eulerosv2r11", rls:"EULEROSVIRT-2.11.0"))) {
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
