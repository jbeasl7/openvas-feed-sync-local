# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2024.1692");
  script_cve_id("CVE-2022-27635", "CVE-2022-36351", "CVE-2022-38076", "CVE-2022-40964");
  script_tag(name:"creation_date", value:"2024-05-17 04:13:21 +0000 (Fri, 17 May 2024)");
  script_version("2024-05-17T05:05:27+0000");
  script_tag(name:"last_modification", value:"2024-05-17 05:05:27 +0000 (Fri, 17 May 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-08-17 17:06:23 +0000 (Thu, 17 Aug 2023)");

  script_name("Huawei EulerOS: Security Advisory for linux-firmware (EulerOS-SA-2024-1692)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROSVIRTARM64\-3\.0\.6\.0");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2024-1692");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2024-1692");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'linux-firmware' package(s) announced via the EulerOS-SA-2024-1692 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Improper access control for some Intel(R) PROSet/Wireless WiFi and Killer(TM) WiFi software may allow a privileged user to potentially enable escalation of privilege via local access.(CVE-2022-40964)

Improper input validation in some Intel(R) PROSet/Wireless WiFi and Killer(TM) WiFi software may allow an authenticated user to potentially enable escalation of privilege via local access.(CVE-2022-38076)

Improper access control for some Intel(R) PROSet/Wireless WiFi and Killer(TM) WiFi software may allow a privileged user to potentially enable escalation of privilege via local access.(CVE-2022-27635)

Improper input validation in some Intel(R) PROSet/Wireless WiFi and Killer(TM) WiFi software may allow an unauthenticated user to potentially enable denial of service via adjacent access.(CVE-2022-36351)");

  script_tag(name:"affected", value:"'linux-firmware' package(s) on Huawei EulerOS Virtualization for ARM 64 3.0.6.0.");

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

if(release == "EULEROSVIRTARM64-3.0.6.0") {

  if(!isnull(res = isrpmvuln(pkg:"libertas-sd8686-firmware", rpm:"libertas-sd8686-firmware~20180913~87.git44d4fca9.h6.eulerosv2r8", rls:"EULEROSVIRTARM64-3.0.6.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libertas-sd8787-firmware", rpm:"libertas-sd8787-firmware~20180913~87.git44d4fca9.h6.eulerosv2r8", rls:"EULEROSVIRTARM64-3.0.6.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libertas-usb8388-firmware", rpm:"libertas-usb8388-firmware~20180913~87.git44d4fca9.h6.eulerosv2r8", rls:"EULEROSVIRTARM64-3.0.6.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libertas-usb8388-olpc-firmware", rpm:"libertas-usb8388-olpc-firmware~20180913~87.git44d4fca9.h6.eulerosv2r8", rls:"EULEROSVIRTARM64-3.0.6.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"linux-firmware", rpm:"linux-firmware~20180913~87.git44d4fca9.h6.eulerosv2r8", rls:"EULEROSVIRTARM64-3.0.6.0"))) {
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
