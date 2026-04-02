# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2026.1472");
  script_cve_id("CVE-2025-54389", "CVE-2025-54409");
  script_tag(name:"creation_date", value:"2026-03-16 13:39:49 +0000 (Mon, 16 Mar 2026)");
  script_version("2026-03-17T05:57:28+0000");
  script_tag(name:"last_modification", value:"2026-03-17 05:57:28 +0000 (Tue, 17 Mar 2026)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-08-19 19:11:40 +0000 (Tue, 19 Aug 2025)");

  script_name("Huawei EulerOS: Security Advisory for aide (EulerOS-SA-2026-1472)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROSVIRT\-2\.12\.0");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2026-1472");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2026-1472");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'aide' package(s) announced via the EulerOS-SA-2026-1472 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"AIDE is an advanced intrusion detection environment. From versions 0.13 to 0.19.1, there is a null pointer dereference vulnerability in AIDE. An attacker can crash the program during report printing or database listing after setting extended file attributes with an empty attribute value or with a key containing a comma. A local user might exploit this to cause a local denial of service. This issue has been patched in version 0.19.2. A workaround involves removing xattrs group from rules matching files on affected file systems.(CVE-2025-54409)

AIDE is an advanced intrusion detection environment. Prior to version 0.19.2, there is an improper output neutralization vulnerability in AIDE. An attacker can craft a malicious filename by including terminal escape sequences to hide the addition or removal of the file from the report and/or tamper with the log output. A local user might exploit this to bypass the AIDE detection of malicious files. Additionally the output of extended attribute key names and symbolic links targets are also not properly neutralized. This issue has been patched in version 0.19.2. A workaround involves configuring AIDE to write the report output to a regular file, redirecting stdout to a regular file, or redirecting the log output written to stderr to a regular file.(CVE-2025-54389)");

  script_tag(name:"affected", value:"'aide' package(s) on Huawei EulerOS Virtualization release 2.12.0.");

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

  if(!isnull(res = isrpmvuln(pkg:"aide", rpm:"aide~0.17.4~1.h5.eulerosv2r12", rls:"EULEROSVIRT-2.12.0"))) {
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
