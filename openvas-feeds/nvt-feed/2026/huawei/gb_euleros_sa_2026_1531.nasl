# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2026.1531");
  script_cve_id("CVE-2025-58436", "CVE-2025-61915");
  script_tag(name:"creation_date", value:"2026-03-16 13:39:49 +0000 (Mon, 16 Mar 2026)");
  script_version("2026-03-17T05:57:28+0000");
  script_tag(name:"last_modification", value:"2026-03-17 05:57:28 +0000 (Tue, 17 Mar 2026)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:M/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-12-04 17:15:19 +0000 (Thu, 04 Dec 2025)");

  script_name("Huawei EulerOS: Security Advisory for cups (EulerOS-SA-2026-1531)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROSVIRT\-2\.10\.1");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2026-1531");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2026-1531");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'cups' package(s) announced via the EulerOS-SA-2026-1531 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"OpenPrinting CUPS is an open source printing system for Linux and other Unix-like operating systems. Prior to version 2.4.15, a user in the lpadmin group can use the cups web ui to change the config and insert a malicious line. Then the cupsd process which runs as root will parse the new config and cause an out-of-bound write. This issue has been patched in version 2.4.15.(CVE-2025-61915)

OpenPrinting CUPS is an open source printing system for Linux and other Unix-like operating systems. Prior to version 2.4.15, a client that connects to cupsd but sends slow messages, e.g. only one byte per second, delays cupsd as a whole, such that it becomes unusable by other clients. This issue has been patched in version 2.4.15.(CVE-2025-58436)");

  script_tag(name:"affected", value:"'cups' package(s) on Huawei EulerOS Virtualization release 2.10.1.");

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

if(release == "EULEROSVIRT-2.10.1") {

  if(!isnull(res = isrpmvuln(pkg:"cups-libs", rpm:"cups-libs~2.2.13~4.h12.eulerosv2r10", rls:"EULEROSVIRT-2.10.1"))) {
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
