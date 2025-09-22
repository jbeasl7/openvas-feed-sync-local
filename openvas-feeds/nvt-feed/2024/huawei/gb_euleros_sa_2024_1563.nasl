# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2024.1563");
  script_cve_id("CVE-2022-41723", "CVE-2023-28840", "CVE-2023-28841", "CVE-2023-28842", "CVE-2023-39325", "CVE-2024-24557");
  script_tag(name:"creation_date", value:"2024-05-10 04:12:42 +0000 (Fri, 10 May 2024)");
  script_version("2025-08-08T05:44:56+0000");
  script_tag(name:"last_modification", value:"2025-08-08 05:44:56 +0000 (Fri, 08 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:N/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:N/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-04-14 15:23:18 +0000 (Fri, 14 Apr 2023)");

  script_name("Huawei EulerOS: Security Advisory for docker-engine (EulerOS-SA-2024-1563)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP10");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2024-1563");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2024-1563");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'docker-engine' package(s) announced via the EulerOS-SA-2024-1563 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Moby is an open-source project created by Docker to enable software containerization. The classic builder cache system is prone to cache poisoning if the image is built FROM scratch. Also, changes to some instructions (most important being HEALTHCHECK and ONBUILD) would not cause a cache miss. An attacker with the knowledge of the Dockerfile someone is using could poison their cache by making them pull a specially crafted image that would be considered as a valid cache candidate for some build steps. 23.0+ users are only affected if they explicitly opted out of Buildkit (DOCKER_BUILDKIT=0 environment variable) or are using the /build API endpoint. All users on versions older than 23.0 could be impacted. Image build API endpoint (/build) and ImageBuild function from github.com/docker/docker/client is also affected as it the uses classic builder by default. Patches are included in 24.0.9 and 25.0.2 releases.(CVE-2024-24557)

A maliciously crafted HTTP/2 stream could cause excessive CPU consumption in the HPACK decoder, sufficient to cause a denial of service from a small number of small requests.(CVE-2022-41723)

A malicious HTTP/2 client which rapidly creates requests and immediately resets them can cause excessive server resource consumption. While the total number of requests is bounded by the http2.Server.MaxConcurrentStreams setting, resetting an in-progress request allows the attacker to create a new request while the existing one is still executing. With the fix applied, HTTP/2 servers now bound the number of simultaneously executing handler goroutines to the stream concurrency limit (MaxConcurrentStreams). New requests arriving when at the limit (which can only happen after the client has reset an existing, in-flight request) will be queued until a handler exits. If the request queue grows too large, the server will terminate the connection. This issue is also fixed in golang.org/x
et/http2 for users manually configuring HTTP/2. The default stream concurrency limit is 250 streams (requests) per HTTP/2 connection. This value may be adjusted using the golang.org/x
et/http2 package, see the Server.MaxConcurrentStreams setting and the ConfigureServer function.(CVE-2023-39325)

Moby is an open source container framework developed by Docker Inc. that is distributed as Docker, Mirantis Container Runtime, and various other downstream projects/products. The Moby daemon component (`dockerd`), which is developed as moby/moby, is commonly referred to as *Docker*.Swarm Mode, which is compiled in and delivered by default in dockerd and is thus present in most major Moby downstreams, is a simple, built-in container orchestrator that is implemented through a combination of SwarmKit and supporting network code.The overlay network driver is a core feature of Swarm Mode, providing isolated virtual LANs that allow communication between containers and services across the cluster. This ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'docker-engine' package(s) on Huawei EulerOS V2.0SP10.");

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

if(release == "EULEROS-2.0SP10") {

  if(!isnull(res = isrpmvuln(pkg:"docker-engine", rpm:"docker-engine~1:18.09.0~200.h82.40.30.eulerosv2r10", rls:"EULEROS-2.0SP10"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker-engine-selinux", rpm:"docker-engine-selinux~1:18.09.0~200.h82.40.30.eulerosv2r10", rls:"EULEROS-2.0SP10"))) {
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
