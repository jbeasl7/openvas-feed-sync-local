# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2024.2063");
  script_cve_id("CVE-2023-6816", "CVE-2024-0229", "CVE-2024-0408", "CVE-2024-0409", "CVE-2024-21885", "CVE-2024-21886");
  script_tag(name:"creation_date", value:"2024-07-24 04:40:56 +0000 (Wed, 24 Jul 2024)");
  script_version("2024-07-24T05:06:37+0000");
  script_tag(name:"last_modification", value:"2024-07-24 05:06:37 +0000 (Wed, 24 Jul 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-01-26 18:50:40 +0000 (Fri, 26 Jan 2024)");

  script_name("Huawei EulerOS: Security Advisory for xorg-x11-server (EulerOS-SA-2024-2063)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP8");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2024-2063");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2024-2063");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'xorg-x11-server' package(s) announced via the EulerOS-SA-2024-2063 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A heap buffer overflow flaw was found in the DisableDevice function in the X.Org server. This issue may lead to an application crash or, in some circumstances, remote code execution in SSH X11 forwarding environments.(CVE-2024-21886)

An out-of-bounds memory access flaw was found in the X.Org server. This issue can be triggered when a device frozen by a sync grab is reattached to a different master device. This issue may lead to an application crash, local privilege escalation (if the server runs with extended privileges), or remote code execution in SSH X11 forwarding environments.(CVE-2024-0229)

A flaw was found in X.Org server. In the XISendDeviceHierarchyEvent function, it is possible to exceed the allocated array length when certain new device IDs are added to the xXIHierarchyInfo struct. This can trigger a heap buffer overflow condition, which may lead to an application crash or remote code execution in SSH X11 forwarding environments.(CVE-2024-21885)

A flaw was found in the X.Org server. The GLX PBuffer code does not call the XACE hook when creating the buffer, leaving it unlabeled. When the client issues another request to access that resource (as with a GetGeometry) or when it creates another resource that needs to access that buffer, such as a GC, the XSELINUX code will try to use an object that was never labeled and crash because the SID is NULL.(CVE-2024-0408)

A flaw was found in X.Org server. Both DeviceFocusEvent and the XIQueryPointer reply contain a bit for each logical button currently down. Buttons can be arbitrarily mapped to any value up to 255, but the X.Org Server was only allocating space for the device's particular number of buttons, leading to a heap overflow if a bigger value was used.(CVE-2023-6816)

A flaw was found in the X.Org server. The cursor code in both Xephyr and Xwayland uses the wrong type of private at creation. It uses the cursor bits type with the cursor as private, and when initiating the cursor, that overwrites the XSELINUX context.(CVE-2024-0409)");

  script_tag(name:"affected", value:"'xorg-x11-server' package(s) on Huawei EulerOS V2.0SP8.");

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

if(release == "EULEROS-2.0SP8") {

  if(!isnull(res = isrpmvuln(pkg:"xorg-x11-server-Xephyr", rpm:"xorg-x11-server-Xephyr~1.20.1~4.h19.eulerosv2r8", rls:"EULEROS-2.0SP8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xorg-x11-server-Xorg", rpm:"xorg-x11-server-Xorg~1.20.1~4.h19.eulerosv2r8", rls:"EULEROS-2.0SP8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xorg-x11-server-Xvfb", rpm:"xorg-x11-server-Xvfb~1.20.1~4.h19.eulerosv2r8", rls:"EULEROS-2.0SP8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xorg-x11-server-Xwayland", rpm:"xorg-x11-server-Xwayland~1.20.1~4.h19.eulerosv2r8", rls:"EULEROS-2.0SP8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xorg-x11-server-common", rpm:"xorg-x11-server-common~1.20.1~4.h19.eulerosv2r8", rls:"EULEROS-2.0SP8"))) {
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
