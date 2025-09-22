# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2025.1683");
  script_cve_id("CVE-2025-0838");
  script_tag(name:"creation_date", value:"2025-06-30 11:34:40 +0000 (Mon, 30 Jun 2025)");
  script_version("2025-08-08T05:44:56+0000");
  script_tag(name:"last_modification", value:"2025-08-08 05:44:56 +0000 (Fri, 08 Aug 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-07-30 18:10:35 +0000 (Wed, 30 Jul 2025)");

  script_name("Huawei EulerOS: Security Advisory for abseil-cpp (EulerOS-SA-2025-1683)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP13");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2025-1683");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2025-1683");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'abseil-cpp' package(s) announced via the EulerOS-SA-2025-1683 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"There exists a heap buffer overflow vulnerable in Abseil-cpp. The sized constructors, reserve(), and rehash() methods of absl::{flat,node}hash{set,map} did not impose an upper bound on their size argument. As a result, it was possible for a caller to pass a very large size that would cause an integer overflow when computing the size of the container's backing store, and a subsequent out-of-bounds memory write. Subsequent accesses to the container might also access out-of-bounds memory. We recommend upgrading past commit 5a0e2cb5e3958dd90bb8569a2766622cb74d90c1(CVE-2025-0838)");

  script_tag(name:"affected", value:"'abseil-cpp' package(s) on Huawei EulerOS V2.0SP13.");

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

if(release == "EULEROS-2.0SP13") {

  if(!isnull(res = isrpmvuln(pkg:"abseil-cpp", rpm:"abseil-cpp~20220623.1~5.h2.eulerosv2r13", rls:"EULEROS-2.0SP13"))) {
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
