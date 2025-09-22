# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2025.1120");
  script_cve_id("CVE-2024-32039", "CVE-2024-32040", "CVE-2024-32041", "CVE-2024-32459", "CVE-2024-32659");
  script_tag(name:"creation_date", value:"2025-01-21 04:31:06 +0000 (Tue, 21 Jan 2025)");
  script_version("2025-08-15T05:40:49+0000");
  script_tag(name:"last_modification", value:"2025-08-15 05:40:49 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-02-04 17:42:16 +0000 (Tue, 04 Feb 2025)");

  script_name("Huawei EulerOS: Security Advisory for freerdp (EulerOS-SA-2025-1120)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP8");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2025-1120");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2025-1120");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'freerdp' package(s) announced via the EulerOS-SA-2025-1120 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"FreeRDP is a free implementation of the Remote Desktop Protocol. FreeRDP based clients and servers that use a version of FreeRDP prior to 3.5.0 or 2.11.6 are vulnerable to out-of-bounds read. Versions 3.5.0 and 2.11.6 patch the issue. No known workarounds are available.(CVE-2024-32459)

FreeRDP is a free implementation of the Remote Desktop Protocol. FreeRDP based clients prior to version 3.5.1 are vulnerable to out-of-bounds read if `((nWidth == 0) and (nHeight == 0))`. Version 3.5.1 contains a patch for the issue. No known workarounds are available.(CVE-2024-32659)

FreeRDP is a free implementation of the Remote Desktop Protocol. FreeRDP based clients using a version of FreeRDP prior to 3.5.0 or 2.11.6 are vulnerable to integer overflow and out-of-bounds write. Versions 3.5.0 and 2.11.6 patch the issue. As a workaround, do not use `/gfx` options (e.g. deactivate with `/bpp:32` or `/rfx` as it is on by default).(CVE-2024-32039)

FreeRDP is a free implementation of the Remote Desktop Protocol. FreeRDP based clients that use a version of FreeRDP prior to 3.5.0 or 2.11.6 and have connections to servers using the `NSC` codec are vulnerable to integer underflow. Versions 3.5.0 and 2.11.6 patch the issue. As a workaround, do not use the NSC codec (e.g. use `-nsc`).(CVE-2024-32040)

FreeRDP is a free implementation of the Remote Desktop Protocol. FreeRDP based clients that use a version of FreeRDP prior to 3.5.0 or 2.11.6 are vulnerable to out-of-bounds read. Versions 3.5.0 and 2.11.6 patch the issue. As a workaround, deactivate `/gfx` (on by default, set `/bpp` or `/rfx` options instead.(CVE-2024-32041)");

  script_tag(name:"affected", value:"'freerdp' package(s) on Huawei EulerOS V2.0SP8.");

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

  if(!isnull(res = isrpmvuln(pkg:"freerdp", rpm:"freerdp~2.0.0~44.rc3.h18.eulerosv2r8", rls:"EULEROS-2.0SP8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freerdp-libs", rpm:"freerdp-libs~2.0.0~44.rc3.h18.eulerosv2r8", rls:"EULEROS-2.0SP8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwinpr", rpm:"libwinpr~2.0.0~44.rc3.h18.eulerosv2r8", rls:"EULEROS-2.0SP8"))) {
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
