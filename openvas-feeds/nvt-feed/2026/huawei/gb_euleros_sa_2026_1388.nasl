# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2026.1388");
  script_cve_id("CVE-2025-52881");
  script_tag(name:"creation_date", value:"2026-03-16 05:12:13 +0000 (Mon, 16 Mar 2026)");
  script_version("2026-03-16T06:13:25+0000");
  script_tag(name:"last_modification", value:"2026-03-16 06:13:25 +0000 (Mon, 16 Mar 2026)");
  script_tag(name:"cvss_base", value:"6.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:H/PR:L/UI:R/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-12-03 18:37:17 +0000 (Wed, 03 Dec 2025)");

  script_name("Huawei EulerOS: Security Advisory for docker-runc (EulerOS-SA-2026-1388)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP12");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2026-1388");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2026-1388");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'docker-runc' package(s) announced via the EulerOS-SA-2026-1388 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"runc is a CLI tool for spawning and running containers according to the OCI specification. In versions 1.2.7, 1.3.2 and 1.4.0-rc.2, an attacker can trick runc into misdirecting writes to /proc to other procfs files through the use of a racing container with shared mounts (we have also verified this attack is possible to exploit using a standard Dockerfile with docker buildx build as that also permits triggering parallel execution of containers with custom shared mounts configured). This redirect could be through symbolic links in a tmpfs or theoretically other methods such as regular bind-mounts. While similar, the mitigation applied for the related CVE, CVE-2019-19921, was fairly limited and effectively only caused runc to verify that when LSM labels are written they are actually procfs files. This issue is fixed in versions 1.2.8, 1.3.3, and 1.4.0-rc.3.(CVE-2025-52881)");

  script_tag(name:"affected", value:"'docker-runc' package(s) on Huawei EulerOS V2.0SP12.");

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

  if(!isnull(res = isrpmvuln(pkg:"docker-runc", rpm:"docker-runc~1.1.3~9.h33.eulerosv2r12", rls:"EULEROS-2.0SP12"))) {
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
