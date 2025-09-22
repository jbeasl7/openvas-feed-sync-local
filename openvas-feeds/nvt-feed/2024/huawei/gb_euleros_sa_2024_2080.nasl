# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2024.2080");
  script_cve_id("CVE-2024-32473");
  script_tag(name:"creation_date", value:"2024-08-09 04:42:35 +0000 (Fri, 09 Aug 2024)");
  script_version("2025-09-05T05:38:20+0000");
  script_tag(name:"last_modification", value:"2025-09-05 05:38:20 +0000 (Fri, 05 Sep 2025)");
  script_tag(name:"cvss_base", value:"6.1");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-09-04 15:09:50 +0000 (Thu, 04 Sep 2025)");

  script_name("Huawei EulerOS: Security Advisory for docker-engine (EulerOS-SA-2024-2080)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP11");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2024-2080");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2024-2080");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'docker-engine' package(s) announced via the EulerOS-SA-2024-2080 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Moby is an open source container framework that is a key component of Docker Engine, Docker Desktop, and other distributions of container tooling or runtimes. In 26.0.0, IPv6 is not disabled on network interfaces, including those belonging to networks where `--ipv6=false`. An container with an `ipvlan` or `macvlan` interface will normally be configured to share an external network link with the host machine. Because of this direct access, (1) Containers may be able to communicate with other hosts on the local network over link-local IPv6 addresses, (2) if router advertisements are being broadcast over the local network, containers may get SLAAC-assigned addresses, and (3) the interface will be a member of IPv6 multicast groups. This means interfaces in IPv4-only networks present an unexpectedly and unnecessarily increased attack surface. The issue is patched in 26.0.2. To completely disable IPv6 in a container, use `--sysctl=net.ipv6.conf.all.disable_ipv6=1` in the `docker create` or `docker run` command. Or, in the service configuration of a `compose` file.(CVE-2024-32473)");

  script_tag(name:"affected", value:"'docker-engine' package(s) on Huawei EulerOS V2.0SP11.");

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

if(release == "EULEROS-2.0SP11") {

  if(!isnull(res = isrpmvuln(pkg:"docker-engine", rpm:"docker-engine~18.09.0~300.h54.47.43.eulerosv2r11", rls:"EULEROS-2.0SP11"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker-engine-selinux", rpm:"docker-engine-selinux~18.09.0~300.h54.47.43.eulerosv2r11", rls:"EULEROS-2.0SP11"))) {
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
