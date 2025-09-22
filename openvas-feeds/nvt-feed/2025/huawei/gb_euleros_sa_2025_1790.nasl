# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2025.1790");
  script_cve_id("CVE-2025-26594", "CVE-2025-26595", "CVE-2025-26596", "CVE-2025-26597", "CVE-2025-26598", "CVE-2025-26599", "CVE-2025-26600", "CVE-2025-26601");
  script_tag(name:"creation_date", value:"2025-07-11 04:39:00 +0000 (Fri, 11 Jul 2025)");
  script_version("2025-07-11T15:43:14+0000");
  script_tag(name:"last_modification", value:"2025-07-11 15:43:14 +0000 (Fri, 11 Jul 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-02-25 16:15:39 +0000 (Tue, 25 Feb 2025)");

  script_name("Huawei EulerOS: Security Advisory for xorg-x11-server (EulerOS-SA-2025-1790)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP10");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2025-1790");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2025-1790");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'xorg-x11-server' package(s) announced via the EulerOS-SA-2025-1790 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A use-after-free flaw was found in X.Org and Xwayland. When changing an alarm, the values of the change mask are evaluated one after the other, changing the trigger values as requested, and eventually, SyncInitTrigger() is called. If one of the changes triggers an error, the function will return early, not adding the new sync object, possibly causing a use-after-free when the alarm eventually triggers.(CVE-2025-26601)

A heap overflow flaw was found in X.Org and Xwayland. The computation of the length in XkbSizeKeySyms() differs from what is written in XkbWriteKeySyms(), which may lead to a heap-based buffer overflow.(CVE-2025-26596)

A buffer overflow flaw was found in X.Org and Xwayland. The code in XkbVModMaskText() allocates a fixed-sized buffer on the stack and copies the names of the virtual modifiers to that buffer. The code fails to check the bounds of the buffer and would copy the data regardless of the size.(CVE-2025-26595)

An access to an uninitialized pointer flaw was found in X.Org and Xwayland. The function compCheckRedirect() may fail if it cannot allocate the backing pixmap. In that case, compRedirectWindow() will return a BadAlloc error without validating the window tree marked just before, which leaves the validated data partly initialized and the use of an uninitialized pointer later.(CVE-2025-26599)

A buffer overflow flaw was found in X.Org and Xwayland. If XkbChangeTypesOfKey() is called with a 0 group, it will resize the key symbols table to 0 but leave the key actions unchanged. If the same function is later called with a non-zero value of groups, this will cause a buffer overflow because the key actions are of the wrong size.(CVE-2025-26597)

A use-after-free flaw was found in X.Org and Xwayland. The root cursor is referenced in the X server as a global variable. If a client frees the root cursor, the internal reference points to freed memory and causes a use-after-free.(CVE-2025-26594)

A use-after-free flaw was found in X.Org and Xwayland. When a device is removed while still frozen, the events queued for that device remain while the device is freed. Replaying the events will cause a use-after-free.(CVE-2025-26600)

An out-of-bounds write flaw was found in X.Org and Xwayland. The function GetBarrierDevice() searches for the pointer device based on its device ID and returns the matching value, or supposedly NULL, if no match was found. However, the code will return the last element of the list if no matching device ID is found, which can lead to out-of-bounds memory access.(CVE-2025-26598)");

  script_tag(name:"affected", value:"'xorg-x11-server' package(s) on Huawei EulerOS V2.0SP10.");

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

  if(!isnull(res = isrpmvuln(pkg:"xorg-x11-server-help", rpm:"xorg-x11-server-help~1.20.8~4.h18.eulerosv2r10", rls:"EULEROS-2.0SP10"))) {
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
