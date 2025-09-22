# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2024.2301");
  script_cve_id("CVE-2022-3550", "CVE-2022-3551", "CVE-2022-4283", "CVE-2022-46340", "CVE-2022-46341", "CVE-2022-46342", "CVE-2022-46343", "CVE-2022-46344", "CVE-2023-0494", "CVE-2023-1393");
  script_tag(name:"creation_date", value:"2024-08-22 04:43:34 +0000 (Thu, 22 Aug 2024)");
  script_version("2024-08-22T05:05:50+0000");
  script_tag(name:"last_modification", value:"2024-08-22 05:05:50 +0000 (Thu, 22 Aug 2024)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-12-19 20:32:49 +0000 (Mon, 19 Dec 2022)");

  script_name("Huawei EulerOS: Security Advisory for xorg-x11-server (EulerOS-SA-2024-2301)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROSVIRTARM64\-3\.0\.2\.0");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2024-2301");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2024-2301");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'xorg-x11-server' package(s) announced via the EulerOS-SA-2024-2301 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A vulnerability, which was classified as problematic, has been found in X.org Server. Affected by this issue is the function ProcXkbGetKbdByName of the file xkb/xkb.c. The manipulation leads to memory leak. It is recommended to apply a patch to fix this issue. The identifier of this vulnerability is VDB-211052.(CVE-2022-3551)

A vulnerability classified as critical was found in X.org Server. Affected by this vulnerability is the function _GetCountedString of the file xkb/xkb.c. The manipulation leads to buffer overflow. It is recommended to apply a patch to fix this issue. The associated identifier of this vulnerability is VDB-211051.(CVE-2022-3550)

A vulnerability was found in X.Org. This security flaw occurs because the XkbCopyNames function left a dangling pointer to freed memory, resulting in out-of-bounds memory access on subsequent XkbGetKbdByName requests.. This issue can lead to local privileges elevation on systems where the X server is running privileged and remote code execution for ssh X forwarding sessions.(CVE-2022-4283)

A vulnerability was found in X.Org. This security flaw occurs because the handler for the XIChangeProperty request has a length-validation issues, resulting in out-of-bounds memory reads and potential information disclosure. This issue can lead to local privileges elevation on systems where the X server is running privileged and remote code execution for ssh X forwarding sessions.(CVE-2022-46344)

A vulnerability was found in X.Org. This security flaw occurs because the handler for the ScreenSaverSetAttributes request may write to memory after it has been freed. This issue can lead to local privileges elevation on systems where the X server is running privileged and remote code execution for ssh X forwarding sessions.(CVE-2022-46343)

A vulnerability was found in X.Org. This security flaw occurs because the handler for the XvdiSelectVideoNotify request may write to memory after it has been freed. This issue can lead to local privileges elevation on systems where the X se(CVE-2022-46342)

A vulnerability was found in X.Org. This security flaw occurs because the handler for the XIPassiveUngrab request accesses out-of-bounds memory when invoked with a high keycode or button code. This issue can lead to local privileges elevation on systems where the X server is running privileged and remote code execution for ssh X forwarding sessions.(CVE-2022-46341)

A vulnerability was found in X.Org. This security flaw occurs becuase the swap handler for the XTestFakeInput request of the XTest extension may corrupt the stack if GenericEvents with lengths larger than 32 bytes are sent through a the XTestFakeInput request. This issue can lead to local privileges elevation on systems where the X server is running privileged and remote code execution for ssh X forwarding sessions. This issue does not affect systems where client and server use the same byte ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'xorg-x11-server' package(s) on Huawei EulerOS Virtualization for ARM 64 3.0.2.0.");

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

if(release == "EULEROSVIRTARM64-3.0.2.0") {

  if(!isnull(res = isrpmvuln(pkg:"xorg-x11-server-Xorg", rpm:"xorg-x11-server-Xorg~1.19.5~5.h20", rls:"EULEROSVIRTARM64-3.0.2.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xorg-x11-server-common", rpm:"xorg-x11-server-common~1.19.5~5.h20", rls:"EULEROSVIRTARM64-3.0.2.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xorg-x11-xkb-utils", rpm:"xorg-x11-xkb-utils~7.7~12", rls:"EULEROSVIRTARM64-3.0.2.0"))) {
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
