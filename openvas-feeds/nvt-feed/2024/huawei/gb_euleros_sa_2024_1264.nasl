# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2024.1264");
  script_cve_id("CVE-2023-39350", "CVE-2023-39353", "CVE-2023-39354", "CVE-2023-39356", "CVE-2023-40181", "CVE-2023-40186", "CVE-2023-40188", "CVE-2023-40567", "CVE-2023-40569", "CVE-2023-40589");
  script_tag(name:"creation_date", value:"2024-03-12 04:24:08 +0000 (Tue, 12 Mar 2024)");
  script_version("2024-03-12T05:06:30+0000");
  script_tag(name:"last_modification", value:"2024-03-12 05:06:30 +0000 (Tue, 12 Mar 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-09-06 20:31:55 +0000 (Wed, 06 Sep 2023)");

  script_name("Huawei EulerOS: Security Advisory for freerdp (EulerOS-SA-2024-1264)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP8");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2024-1264");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2024-1264");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'freerdp' package(s) announced via the EulerOS-SA-2024-1264 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"FreeRDP is a free implementation of the Remote Desktop Protocol (RDP), released under the Apache license. Affected versions are subject to an Out-Of-Bounds Read in the `nsc_rle_decompress_data` function. The Out-Of-Bounds Read occurs because it processes `context->Planes` without checking if it contains data of sufficient length. Should an attacker be able to leverage this vulnerability they may be able to cause a crash. This issue has been addressed in versions 2.11.0 and 3.0.0-beta3. Users are advised to upgrade. There are no known workarounds for this vulnerability.(CVE-2023-39354)

FreeRDP is a free implementation of the Remote Desktop Protocol (RDP), released under the Apache license. This issue affects Clients only. Integer underflow leading to DOS (e.g. abort due to `WINPR_ASSERT` with default compilation flags). When an insufficient blockLen is provided, and proper length validation is not performed, an Integer Underflow occurs, leading to a Denial of Service (DOS) vulnerability. This issue has been addressed in versions 2.11.0 and 3.0.0-beta3. Users are advised to upgrade. There are no known workarounds for this vulnerability.(CVE-2023-39350)

FreeRDP is a free implementation of the Remote Desktop Protocol (RDP), released under the Apache license. In affected versions there is a Global-Buffer-Overflow in the ncrush_decompress function. Feeding crafted input into this function can trigger the overflow which has only been shown to cause a crash. This issue has been addressed in versions 2.11.0 and 3.0.0-beta3. Users are advised to upgrade. There are no known workarounds for this issue.(CVE-2023-40589)

FreeRDP is a free implementation of the Remote Desktop Protocol (RDP), released under the Apache license. In affected versions a missing offset validation may lead to an Out Of Bound Read in the function `gdi_multi_opaque_rect`. In particular there is no code to validate if the value `multi_opaque_rect->numRectangles` is less than 45. Looping through `multi_opaque_rect->`numRectangles without proper boundary checks can lead to Out-of-Bounds Read errors which will likely lead to a crash. This issue has been addressed in versions 2.11.0 and 3.0.0-beta3. Users are advised to upgrade. There are no known workarounds for this vulnerability.(CVE-2023-39356)

FreeRDP is a free implementation of the Remote Desktop Protocol (RDP), released under the Apache license. Affected versions are subject to an Out-Of-Bounds Write in the `progressive_decompress` function. This issue is likely down to incorrect calculations of the `nXSrc` and `nYSrc` variables. This issue has been addressed in versions 2.11.0 and 3.0.0-beta3. Users are advised to upgrade. there are no known workarounds for this vulnerability.(CVE-2023-40569)

FreeRDP is a free implementation of the Remote Desktop Protocol (RDP), released under the Apache license. Affected versions are subject to an IntegerOverflow ... [Please see the references for more information on the vulnerabilities]");

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

  if(!isnull(res = isrpmvuln(pkg:"freerdp", rpm:"freerdp~2.0.0~44.rc3.h16.eulerosv2r8", rls:"EULEROS-2.0SP8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freerdp-libs", rpm:"freerdp-libs~2.0.0~44.rc3.h16.eulerosv2r8", rls:"EULEROS-2.0SP8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwinpr", rpm:"libwinpr~2.0.0~44.rc3.h16.eulerosv2r8", rls:"EULEROS-2.0SP8"))) {
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
