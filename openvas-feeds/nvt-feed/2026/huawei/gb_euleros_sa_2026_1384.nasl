# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2026.1384");
  script_cve_id("CVE-2024-25621", "CVE-2025-64329");
  script_tag(name:"creation_date", value:"2026-03-16 05:12:13 +0000 (Mon, 16 Mar 2026)");
  script_version("2026-03-16T06:13:25+0000");
  script_tag(name:"last_modification", value:"2026-03-16 06:13:25 +0000 (Mon, 16 Mar 2026)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-12-31 02:29:30 +0000 (Wed, 31 Dec 2025)");

  script_name("Huawei EulerOS: Security Advisory for containerd (EulerOS-SA-2026-1384)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP12");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2026-1384");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2026-1384");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'containerd' package(s) announced via the EulerOS-SA-2026-1384 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"containerd is an open-source container runtime. Versions 1.7.28 and below, 2.0.0-beta.0 through 2.0.6, 2.1.0-beta.0 through 2.1.4, and 2.2.0-beta.0 through 2.2.0-rc.1 contain a bug in the CRI Attach implementation where a user can exhaust memory on the host due to goroutine leaks. This issue is fixed in versions 1.7.29, 2.0.7, 2.1.5 and 2.2.0. To workaround this vulnerability, users can set up an admission controller to control accesses to pods/attach resources.(CVE-2025-64329)

containerd is an open-source container runtime. Versions 0.1.0 through 1.7.28, 2.0.0-beta.0 through 2.0.6, 2.1.0-beta.0 through 2.1.4 and 2.2.0-beta.0 through 2.2.0-rc.1 have an overly broad default permission vulnerability. Directory paths `/var/lib/containerd`, `/run/containerd/io.containerd.grpc.v1.cri` and `/run/containerd/io.containerd.sandbox.controller.v1.shim` were all created with incorrect permissions. This issue is fixed in versions 1.7.29, 2.0.7, 2.1.5 and 2.2.0. Workarounds include updating system administrator permissions so the host can manually chmod the directories to not have group or world accessible permissions, or to run containerd in rootless mode.(CVE-2024-25621)");

  script_tag(name:"affected", value:"'containerd' package(s) on Huawei EulerOS V2.0SP12.");

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

if(release == "EULEROS-2.0SP12") {

  if(!isnull(res = isrpmvuln(pkg:"docker-engine", rpm:"docker-engine~18.09.0~400.h55.53.60.eulerosv2r12", rls:"EULEROS-2.0SP12"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker-engine-selinux", rpm:"docker-engine-selinux~18.09.0~400.h55.53.60.eulerosv2r12", rls:"EULEROS-2.0SP12"))) {
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
