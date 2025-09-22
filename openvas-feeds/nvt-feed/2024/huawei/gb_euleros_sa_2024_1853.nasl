# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2024.1853");
  script_cve_id("CVE-2023-25809");
  script_tag(name:"creation_date", value:"2024-07-01 04:14:03 +0000 (Mon, 01 Jul 2024)");
  script_version("2024-07-01T05:05:38+0000");
  script_tag(name:"last_modification", value:"2024-07-01 05:05:38 +0000 (Mon, 01 Jul 2024)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:L");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-04-06 17:41:26 +0000 (Thu, 06 Apr 2023)");

  script_name("Huawei EulerOS: Security Advisory for docker-runc (EulerOS-SA-2024-1853)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP12");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2024-1853");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2024-1853");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'docker-runc' package(s) announced via the EulerOS-SA-2024-1853 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"runc is a CLI tool for spawning and running containers according to the OCI specification. In affected versions it was found that rootless runc makes `/sys/fs/cgroup` writable in following conditons: 1. when runc is executed inside the user namespace, and the `config.json` does not specify the cgroup namespace to be unshared (e.g.., `(docker<pipe>podman<pipe>nerdctl) run --cgroupns=host`, with Rootless Docker/Podman/nerdctl) or 2. when runc is executed outside the user namespace, and `/sys` is mounted with `rbind, ro` (e.g., `runc spec --rootless`, this condition is very rare). A container may gain the write access to user-owned cgroup hierarchy `/sys/fs/cgroup/user.slice/...` on the host . Other users's cgroup hierarchies are not affected. Users are advised to upgrade to version 1.1.5. Users unable to upgrade may unshare the cgroup namespace (`(docker<pipe>podman<pipe>nerdctl) run --cgroupns=private)`. This is the default behavior of Docker/Podman/nerdctl on cgroup v2 hosts. or add `/sys/fs/cgroup` to `maskedPaths`.(CVE-2023-25809)");

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

  if(!isnull(res = isrpmvuln(pkg:"docker-runc", rpm:"docker-runc~1.1.3~9.h24.eulerosv2r12", rls:"EULEROS-2.0SP12"))) {
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
