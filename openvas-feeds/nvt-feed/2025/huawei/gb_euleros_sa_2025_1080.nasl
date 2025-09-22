# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2025.1080");
  script_cve_id("CVE-2024-43167", "CVE-2024-43168");
  script_tag(name:"creation_date", value:"2025-02-05 04:31:15 +0000 (Wed, 05 Feb 2025)");
  script_version("2025-02-05T05:38:26+0000");
  script_tag(name:"last_modification", value:"2025-02-05 05:38:26 +0000 (Wed, 05 Feb 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Huawei EulerOS: Security Advisory for unbound (EulerOS-SA-2025-1080)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROSVIRT\-2\.12\.0");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2025-1080");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2025-1080");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'unbound' package(s) announced via the EulerOS-SA-2025-1080 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"DISPUTE NOTE: this issue does not pose a security risk as it (according to analysis by the original software developer, NLnet Labs) falls within the expected functionality and security controls of the application. Red Hat has made a claim that there is a security risk within Red Hat products. NLnet Labs has no further information about the claim, and suggests that affected Red Hat customers refer to available Red Hat documentation or support channels. ORIGINAL DESCRIPTION: A NULL pointer dereference flaw was found in the ub_ctx_set_fwd function in Unbound. This issue could allow an attacker who can invoke specific sequences of API calls to cause a segmentation fault. When certain API functions such as ub_ctx_set_fwd and ub_ctx_resolvconf are called in a particular order, the program attempts to read from a NULL pointer, leading to a crash. This issue can result in a denial of service by causing the application to terminate unexpectedly.(CVE-2024-43167)

A heap-buffer-overflow flaw was found in the cfg_mark_ports function within Unbound's config_file.c, which can lead to memory corruption.This issue could allow an attacker with local access to provide specially crafted input, potentially causing the application to crash or allowing arbitrary code execution.This could result in a denial of service or unauthorized actions on the system.(CVE-2024-43168)");

  script_tag(name:"affected", value:"'unbound' package(s) on Huawei EulerOS Virtualization release 2.12.0.");

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

if(release == "EULEROSVIRT-2.12.0") {

  if(!isnull(res = isrpmvuln(pkg:"python3-unbound", rpm:"python3-unbound~1.13.2~7.h4.eulerosv2r12", rls:"EULEROSVIRT-2.12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"unbound", rpm:"unbound~1.13.2~7.h4.eulerosv2r12", rls:"EULEROSVIRT-2.12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"unbound-libs", rpm:"unbound-libs~1.13.2~7.h4.eulerosv2r12", rls:"EULEROSVIRT-2.12.0"))) {
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
