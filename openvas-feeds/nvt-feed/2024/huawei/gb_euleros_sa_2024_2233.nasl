# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2024.2233");
  script_cve_id("CVE-2024-29018");
  script_tag(name:"creation_date", value:"2024-08-21 04:43:08 +0000 (Wed, 21 Aug 2024)");
  script_version("2025-05-01T05:40:03+0000");
  script_tag(name:"last_modification", value:"2025-05-01 05:40:03 +0000 (Thu, 01 May 2025)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-04-09 15:40:20 +0000 (Wed, 09 Apr 2025)");

  script_name("Huawei EulerOS: Security Advisory for docker-engine (EulerOS-SA-2024-2233)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP12\-X86_64");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2024-2233");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2024-2233");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'docker-engine' package(s) announced via the EulerOS-SA-2024-2233 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Moby is an open source container framework that is a key component of Docker Engine, Docker Desktop, and other distributions of container tooling or runtimes. Moby's networking implementation allows for many networks, each with their own IP address range and gateway, to be defined. This feature is frequently referred to as custom networks, as each network can have a different driver, set of parameters and thus behaviors. When creating a network, the `--internal` flag is used to designate a network as _internal_. The `internal` attribute in a docker-compose.yml file may also be used to mark a network _internal_, and other API clients may specify the `internal` parameter as well. When containers with networking are created, they are assigned unique network interfaces and IP addresses. The host serves as a router for non-internal networks, with a gateway IP that provides SNAT/DNAT to/from container IPs. Containers on an internal network may communicate between each other, but are precluded from communicating with any networks the host has access to (LAN or WAN) as no default route is configured, and firewall rules are set up to drop all outgoing traffic. Communication with the gateway IP address (and thus appropriately configured host services) is possible, and the host may communicate with any container IP directly. In addition to configuring the Linux kernel's various networking features to enable container networking, `dockerd` directly provides some services to container networks. Principal among these is serving as a resolver, enabling service discovery, and resolution of names from an upstream resolver. When a DNS request for a name that does not correspond to a container is received, the request is forwarded to the configured upstream resolver. This request is made from the container's network namespace: the level of access and routing of traffic is the same as if the request was made by the container itself. As a consequence of this design, containers solely attached to an internal network will be unable to resolve names using the upstream resolver, as the container itself is unable to communicate with that nameserver. Only the names of containers also attached to the internal network are able to be resolved. Many systems run a local forwarding DNS resolver. As the host and any containers have separate loopback devices, a consequence of the design described above is that containers are unable to resolve names from the host's configured resolver, as they cannot reach these addresses on the host loopback device. To bridge this gap, and to allow containers to properly resolve names even when a local forwarding resolver is used on a loopback address, `dockerd` detects this scenario and instead forward DNS requests from the host namework namespace. The loopback resolver then forwards the requests to its configured upstream resolvers, as expected. Because `dockerd` ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'docker-engine' package(s) on Huawei EulerOS V2.0SP12(x86_64).");

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

if(release == "EULEROS-2.0SP12-x86_64") {

  if(!isnull(res = isrpmvuln(pkg:"docker-engine", rpm:"docker-engine~18.09.0~400.h36.50.48.eulerosv2r12", rls:"EULEROS-2.0SP12-x86_64"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker-engine-selinux", rpm:"docker-engine-selinux~18.09.0~400.h36.50.48.eulerosv2r12", rls:"EULEROS-2.0SP12-x86_64"))) {
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
