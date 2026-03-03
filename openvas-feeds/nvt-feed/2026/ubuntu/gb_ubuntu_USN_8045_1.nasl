# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2026.8045.1");
  script_cve_id("CVE-2024-31884", "CVE-2024-47866");
  script_tag(name:"creation_date", value:"2026-03-02 04:35:29 +0000 (Mon, 02 Mar 2026)");
  script_version("2026-03-02T05:55:30+0000");
  script_tag(name:"last_modification", value:"2026-03-02 05:55:30 +0000 (Mon, 02 Mar 2026)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Ubuntu: Security Advisory (USN-8045-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(14\.04\ LTS|16\.04\ LTS|18\.04\ LTS|20\.04\ LTS|22\.04\ LTS|24\.04\ LTS|25\.10)");

  script_xref(name:"Advisory-ID", value:"USN-8045-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-8045-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ceph' package(s) announced via the USN-8045-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Martin Schobert discovered that Ceph did not properly verify SSL
certificates when using Pybind for secure mail connections, which could
result in accepting invalid certificates. An attacker could possibly use
this issue to perform an intermediary attack and access mail server
credentials or message contents. This issue only affected Ubuntu 20.04 LTS,
Ubuntu 22.04 LTS, Ubuntu 24.04 LTS and Ubuntu 25.10. (CVE-2024-31884)

It was discovered that Ceph's RADOS Gateway (RGW) did not properly handle
certain header parameters. An attacker could possibly use this issue to
cause the RGW service to crash, leading to a denial of service.
(CVE-2024-47866)");

  script_tag(name:"affected", value:"'ceph' package(s) on Ubuntu 14.04, Ubuntu 16.04, Ubuntu 18.04, Ubuntu 20.04, Ubuntu 22.04, Ubuntu 24.04, Ubuntu 25.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

release = dpkg_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "UBUNTU14.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"ceph", ver:"0.80.11-0ubuntu1.14.04.4+esm4", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ceph-common", ver:"0.80.11-0ubuntu1.14.04.4+esm4", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ceph-fs-common", ver:"0.80.11-0ubuntu1.14.04.4+esm4", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ceph-fuse", ver:"0.80.11-0ubuntu1.14.04.4+esm4", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ceph-mds", ver:"0.80.11-0ubuntu1.14.04.4+esm4", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ceph-resource-agents", ver:"0.80.11-0ubuntu1.14.04.4+esm4", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ceph-test", ver:"0.80.11-0ubuntu1.14.04.4+esm4", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libcephfs-dev", ver:"0.80.11-0ubuntu1.14.04.4+esm4", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libcephfs-java", ver:"0.80.11-0ubuntu1.14.04.4+esm4", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libcephfs-jni", ver:"0.80.11-0ubuntu1.14.04.4+esm4", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libcephfs1", ver:"0.80.11-0ubuntu1.14.04.4+esm4", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"librados-dev", ver:"0.80.11-0ubuntu1.14.04.4+esm4", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"librados2", ver:"0.80.11-0ubuntu1.14.04.4+esm4", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"librbd-dev", ver:"0.80.11-0ubuntu1.14.04.4+esm4", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"librbd1", ver:"0.80.11-0ubuntu1.14.04.4+esm4", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python-ceph", ver:"0.80.11-0ubuntu1.14.04.4+esm4", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"radosgw", ver:"0.80.11-0ubuntu1.14.04.4+esm4", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"rbd-fuse", ver:"0.80.11-0ubuntu1.14.04.4+esm4", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"rest-bench", ver:"0.80.11-0ubuntu1.14.04.4+esm4", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU16.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"ceph", ver:"10.2.11-0ubuntu0.16.04.3+esm3", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ceph-common", ver:"10.2.11-0ubuntu0.16.04.3+esm3", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ceph-fs-common", ver:"10.2.11-0ubuntu0.16.04.3+esm3", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ceph-fuse", ver:"10.2.11-0ubuntu0.16.04.3+esm3", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ceph-mds", ver:"10.2.11-0ubuntu0.16.04.3+esm3", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ceph-resource-agents", ver:"10.2.11-0ubuntu0.16.04.3+esm3", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ceph-test", ver:"10.2.11-0ubuntu0.16.04.3+esm3", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libcephfs-dev", ver:"10.2.11-0ubuntu0.16.04.3+esm3", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libcephfs-java", ver:"10.2.11-0ubuntu0.16.04.3+esm3", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libcephfs-jni", ver:"10.2.11-0ubuntu0.16.04.3+esm3", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libcephfs1", ver:"10.2.11-0ubuntu0.16.04.3+esm3", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"librados-dev", ver:"10.2.11-0ubuntu0.16.04.3+esm3", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"librados2", ver:"10.2.11-0ubuntu0.16.04.3+esm3", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libradosstriper-dev", ver:"10.2.11-0ubuntu0.16.04.3+esm3", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libradosstriper1", ver:"10.2.11-0ubuntu0.16.04.3+esm3", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"librbd-dev", ver:"10.2.11-0ubuntu0.16.04.3+esm3", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"librbd1", ver:"10.2.11-0ubuntu0.16.04.3+esm3", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"librgw-dev", ver:"10.2.11-0ubuntu0.16.04.3+esm3", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"librgw2", ver:"10.2.11-0ubuntu0.16.04.3+esm3", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python-ceph", ver:"10.2.11-0ubuntu0.16.04.3+esm3", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python-cephfs", ver:"10.2.11-0ubuntu0.16.04.3+esm3", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python-rados", ver:"10.2.11-0ubuntu0.16.04.3+esm3", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python-rbd", ver:"10.2.11-0ubuntu0.16.04.3+esm3", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"radosgw", ver:"10.2.11-0ubuntu0.16.04.3+esm3", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"rbd-fuse", ver:"10.2.11-0ubuntu0.16.04.3+esm3", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"rbd-mirror", ver:"10.2.11-0ubuntu0.16.04.3+esm3", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"rbd-nbd", ver:"10.2.11-0ubuntu0.16.04.3+esm3", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU18.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"ceph", ver:"12.2.13-0ubuntu0.18.04.11+esm2", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ceph-base", ver:"12.2.13-0ubuntu0.18.04.11+esm2", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ceph-common", ver:"12.2.13-0ubuntu0.18.04.11+esm2", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ceph-fuse", ver:"12.2.13-0ubuntu0.18.04.11+esm2", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ceph-mds", ver:"12.2.13-0ubuntu0.18.04.11+esm2", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ceph-mgr", ver:"12.2.13-0ubuntu0.18.04.11+esm2", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ceph-mon", ver:"12.2.13-0ubuntu0.18.04.11+esm2", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ceph-osd", ver:"12.2.13-0ubuntu0.18.04.11+esm2", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ceph-resource-agents", ver:"12.2.13-0ubuntu0.18.04.11+esm2", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ceph-test", ver:"12.2.13-0ubuntu0.18.04.11+esm2", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libcephfs-dev", ver:"12.2.13-0ubuntu0.18.04.11+esm2", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libcephfs-java", ver:"12.2.13-0ubuntu0.18.04.11+esm2", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libcephfs-jni", ver:"12.2.13-0ubuntu0.18.04.11+esm2", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libcephfs2", ver:"12.2.13-0ubuntu0.18.04.11+esm2", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"librados-dev", ver:"12.2.13-0ubuntu0.18.04.11+esm2", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"librados2", ver:"12.2.13-0ubuntu0.18.04.11+esm2", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libradosstriper-dev", ver:"12.2.13-0ubuntu0.18.04.11+esm2", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libradosstriper1", ver:"12.2.13-0ubuntu0.18.04.11+esm2", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"librbd-dev", ver:"12.2.13-0ubuntu0.18.04.11+esm2", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"librbd1", ver:"12.2.13-0ubuntu0.18.04.11+esm2", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"librgw-dev", ver:"12.2.13-0ubuntu0.18.04.11+esm2", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"librgw2", ver:"12.2.13-0ubuntu0.18.04.11+esm2", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python-ceph", ver:"12.2.13-0ubuntu0.18.04.11+esm2", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python-cephfs", ver:"12.2.13-0ubuntu0.18.04.11+esm2", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python-rados", ver:"12.2.13-0ubuntu0.18.04.11+esm2", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python-rbd", ver:"12.2.13-0ubuntu0.18.04.11+esm2", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python-rgw", ver:"12.2.13-0ubuntu0.18.04.11+esm2", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python3-ceph-argparse", ver:"12.2.13-0ubuntu0.18.04.11+esm2", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python3-cephfs", ver:"12.2.13-0ubuntu0.18.04.11+esm2", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python3-rados", ver:"12.2.13-0ubuntu0.18.04.11+esm2", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python3-rbd", ver:"12.2.13-0ubuntu0.18.04.11+esm2", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python3-rgw", ver:"12.2.13-0ubuntu0.18.04.11+esm2", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"rados-objclass-dev", ver:"12.2.13-0ubuntu0.18.04.11+esm2", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"radosgw", ver:"12.2.13-0ubuntu0.18.04.11+esm2", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"rbd-fuse", ver:"12.2.13-0ubuntu0.18.04.11+esm2", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"rbd-mirror", ver:"12.2.13-0ubuntu0.18.04.11+esm2", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"rbd-nbd", ver:"12.2.13-0ubuntu0.18.04.11+esm2", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU20.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"ceph", ver:"15.2.17-0ubuntu0.20.04.6+esm1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ceph-base", ver:"15.2.17-0ubuntu0.20.04.6+esm1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ceph-common", ver:"15.2.17-0ubuntu0.20.04.6+esm1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ceph-fuse", ver:"15.2.17-0ubuntu0.20.04.6+esm1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ceph-immutable-object-cache", ver:"15.2.17-0ubuntu0.20.04.6+esm1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ceph-mds", ver:"15.2.17-0ubuntu0.20.04.6+esm1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ceph-mgr", ver:"15.2.17-0ubuntu0.20.04.6+esm1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ceph-mgr-cephadm", ver:"15.2.17-0ubuntu0.20.04.6+esm1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ceph-mgr-dashboard", ver:"15.2.17-0ubuntu0.20.04.6+esm1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ceph-mgr-diskprediction-cloud", ver:"15.2.17-0ubuntu0.20.04.6+esm1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ceph-mgr-diskprediction-local", ver:"15.2.17-0ubuntu0.20.04.6+esm1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ceph-mgr-k8sevents", ver:"15.2.17-0ubuntu0.20.04.6+esm1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ceph-mgr-modules-core", ver:"15.2.17-0ubuntu0.20.04.6+esm1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ceph-mgr-rook", ver:"15.2.17-0ubuntu0.20.04.6+esm1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ceph-mon", ver:"15.2.17-0ubuntu0.20.04.6+esm1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ceph-osd", ver:"15.2.17-0ubuntu0.20.04.6+esm1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ceph-resource-agents", ver:"15.2.17-0ubuntu0.20.04.6+esm1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cephadm", ver:"15.2.17-0ubuntu0.20.04.6+esm1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cephfs-shell", ver:"15.2.17-0ubuntu0.20.04.6+esm1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libcephfs-dev", ver:"15.2.17-0ubuntu0.20.04.6+esm1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libcephfs-java", ver:"15.2.17-0ubuntu0.20.04.6+esm1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libcephfs-jni", ver:"15.2.17-0ubuntu0.20.04.6+esm1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libcephfs2", ver:"15.2.17-0ubuntu0.20.04.6+esm1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"librados-dev", ver:"15.2.17-0ubuntu0.20.04.6+esm1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"librados2", ver:"15.2.17-0ubuntu0.20.04.6+esm1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libradospp-dev", ver:"15.2.17-0ubuntu0.20.04.6+esm1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libradosstriper-dev", ver:"15.2.17-0ubuntu0.20.04.6+esm1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libradosstriper1", ver:"15.2.17-0ubuntu0.20.04.6+esm1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"librbd-dev", ver:"15.2.17-0ubuntu0.20.04.6+esm1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"librbd1", ver:"15.2.17-0ubuntu0.20.04.6+esm1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"librgw-dev", ver:"15.2.17-0ubuntu0.20.04.6+esm1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"librgw2", ver:"15.2.17-0ubuntu0.20.04.6+esm1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python3-ceph", ver:"15.2.17-0ubuntu0.20.04.6+esm1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python3-ceph-argparse", ver:"15.2.17-0ubuntu0.20.04.6+esm1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python3-ceph-common", ver:"15.2.17-0ubuntu0.20.04.6+esm1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python3-cephfs", ver:"15.2.17-0ubuntu0.20.04.6+esm1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python3-rados", ver:"15.2.17-0ubuntu0.20.04.6+esm1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python3-rbd", ver:"15.2.17-0ubuntu0.20.04.6+esm1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python3-rgw", ver:"15.2.17-0ubuntu0.20.04.6+esm1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"rados-objclass-dev", ver:"15.2.17-0ubuntu0.20.04.6+esm1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"radosgw", ver:"15.2.17-0ubuntu0.20.04.6+esm1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"rbd-fuse", ver:"15.2.17-0ubuntu0.20.04.6+esm1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"rbd-mirror", ver:"15.2.17-0ubuntu0.20.04.6+esm1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"rbd-nbd", ver:"15.2.17-0ubuntu0.20.04.6+esm1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU22.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"ceph", ver:"17.2.9-0ubuntu0.22.04.2", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ceph-base", ver:"17.2.9-0ubuntu0.22.04.2", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ceph-common", ver:"17.2.9-0ubuntu0.22.04.2", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ceph-fuse", ver:"17.2.9-0ubuntu0.22.04.2", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ceph-grafana-dashboards", ver:"17.2.9-0ubuntu0.22.04.2", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ceph-immutable-object-cache", ver:"17.2.9-0ubuntu0.22.04.2", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ceph-mds", ver:"17.2.9-0ubuntu0.22.04.2", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ceph-mgr", ver:"17.2.9-0ubuntu0.22.04.2", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ceph-mgr-cephadm", ver:"17.2.9-0ubuntu0.22.04.2", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ceph-mgr-dashboard", ver:"17.2.9-0ubuntu0.22.04.2", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ceph-mgr-diskprediction-local", ver:"17.2.9-0ubuntu0.22.04.2", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ceph-mgr-k8sevents", ver:"17.2.9-0ubuntu0.22.04.2", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ceph-mgr-modules-core", ver:"17.2.9-0ubuntu0.22.04.2", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ceph-mgr-rook", ver:"17.2.9-0ubuntu0.22.04.2", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ceph-mon", ver:"17.2.9-0ubuntu0.22.04.2", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ceph-osd", ver:"17.2.9-0ubuntu0.22.04.2", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ceph-prometheus-alerts", ver:"17.2.9-0ubuntu0.22.04.2", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ceph-resource-agents", ver:"17.2.9-0ubuntu0.22.04.2", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ceph-volume", ver:"17.2.9-0ubuntu0.22.04.2", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cephadm", ver:"17.2.9-0ubuntu0.22.04.2", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cephfs-mirror", ver:"17.2.9-0ubuntu0.22.04.2", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cephfs-shell", ver:"17.2.9-0ubuntu0.22.04.2", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crimson-osd", ver:"17.2.9-0ubuntu0.22.04.2", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libcephfs-dev", ver:"17.2.9-0ubuntu0.22.04.2", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libcephfs-java", ver:"17.2.9-0ubuntu0.22.04.2", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libcephfs-jni", ver:"17.2.9-0ubuntu0.22.04.2", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libcephfs2", ver:"17.2.9-0ubuntu0.22.04.2", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"librados-dev", ver:"17.2.9-0ubuntu0.22.04.2", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"librados2", ver:"17.2.9-0ubuntu0.22.04.2", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libradospp-dev", ver:"17.2.9-0ubuntu0.22.04.2", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libradosstriper-dev", ver:"17.2.9-0ubuntu0.22.04.2", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libradosstriper1", ver:"17.2.9-0ubuntu0.22.04.2", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"librbd-dev", ver:"17.2.9-0ubuntu0.22.04.2", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"librbd1", ver:"17.2.9-0ubuntu0.22.04.2", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"librgw-dev", ver:"17.2.9-0ubuntu0.22.04.2", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"librgw2", ver:"17.2.9-0ubuntu0.22.04.2", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libsqlite3-mod-ceph", ver:"17.2.9-0ubuntu0.22.04.2", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libsqlite3-mod-ceph-dev", ver:"17.2.9-0ubuntu0.22.04.2", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python3-ceph", ver:"17.2.9-0ubuntu0.22.04.2", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python3-ceph-argparse", ver:"17.2.9-0ubuntu0.22.04.2", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python3-ceph-common", ver:"17.2.9-0ubuntu0.22.04.2", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python3-cephfs", ver:"17.2.9-0ubuntu0.22.04.2", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python3-rados", ver:"17.2.9-0ubuntu0.22.04.2", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python3-rbd", ver:"17.2.9-0ubuntu0.22.04.2", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python3-rgw", ver:"17.2.9-0ubuntu0.22.04.2", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"rados-objclass-dev", ver:"17.2.9-0ubuntu0.22.04.2", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"radosgw", ver:"17.2.9-0ubuntu0.22.04.2", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"rbd-fuse", ver:"17.2.9-0ubuntu0.22.04.2", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"rbd-mirror", ver:"17.2.9-0ubuntu0.22.04.2", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"rbd-nbd", ver:"17.2.9-0ubuntu0.22.04.2", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU24.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"ceph", ver:"19.2.3-0ubuntu0.24.04.3", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ceph-base", ver:"19.2.3-0ubuntu0.24.04.3", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ceph-common", ver:"19.2.3-0ubuntu0.24.04.3", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ceph-fuse", ver:"19.2.3-0ubuntu0.24.04.3", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ceph-grafana-dashboards", ver:"19.2.3-0ubuntu0.24.04.3", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ceph-immutable-object-cache", ver:"19.2.3-0ubuntu0.24.04.3", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ceph-mds", ver:"19.2.3-0ubuntu0.24.04.3", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ceph-mgr", ver:"19.2.3-0ubuntu0.24.04.3", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ceph-mgr-cephadm", ver:"19.2.3-0ubuntu0.24.04.3", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ceph-mgr-dashboard", ver:"19.2.3-0ubuntu0.24.04.3", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ceph-mgr-diskprediction-local", ver:"19.2.3-0ubuntu0.24.04.3", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ceph-mgr-k8sevents", ver:"19.2.3-0ubuntu0.24.04.3", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ceph-mgr-modules-core", ver:"19.2.3-0ubuntu0.24.04.3", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ceph-mgr-rook", ver:"19.2.3-0ubuntu0.24.04.3", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ceph-mon", ver:"19.2.3-0ubuntu0.24.04.3", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ceph-osd", ver:"19.2.3-0ubuntu0.24.04.3", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ceph-prometheus-alerts", ver:"19.2.3-0ubuntu0.24.04.3", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ceph-resource-agents", ver:"19.2.3-0ubuntu0.24.04.3", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ceph-volume", ver:"19.2.3-0ubuntu0.24.04.3", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cephadm", ver:"19.2.3-0ubuntu0.24.04.3", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cephfs-mirror", ver:"19.2.3-0ubuntu0.24.04.3", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cephfs-shell", ver:"19.2.3-0ubuntu0.24.04.3", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crimson-osd", ver:"19.2.3-0ubuntu0.24.04.3", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libcephfs-dev", ver:"19.2.3-0ubuntu0.24.04.3", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libcephfs-java", ver:"19.2.3-0ubuntu0.24.04.3", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libcephfs-jni", ver:"19.2.3-0ubuntu0.24.04.3", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libcephfs2", ver:"19.2.3-0ubuntu0.24.04.3", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"librados-dev", ver:"19.2.3-0ubuntu0.24.04.3", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"librados2", ver:"19.2.3-0ubuntu0.24.04.3", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libradospp-dev", ver:"19.2.3-0ubuntu0.24.04.3", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libradosstriper-dev", ver:"19.2.3-0ubuntu0.24.04.3", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libradosstriper1", ver:"19.2.3-0ubuntu0.24.04.3", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"librbd-dev", ver:"19.2.3-0ubuntu0.24.04.3", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"librbd1", ver:"19.2.3-0ubuntu0.24.04.3", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"librgw-dev", ver:"19.2.3-0ubuntu0.24.04.3", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"librgw2", ver:"19.2.3-0ubuntu0.24.04.3", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libsqlite3-mod-ceph", ver:"19.2.3-0ubuntu0.24.04.3", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libsqlite3-mod-ceph-dev", ver:"19.2.3-0ubuntu0.24.04.3", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python3-ceph", ver:"19.2.3-0ubuntu0.24.04.3", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python3-ceph-argparse", ver:"19.2.3-0ubuntu0.24.04.3", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python3-ceph-common", ver:"19.2.3-0ubuntu0.24.04.3", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python3-cephfs", ver:"19.2.3-0ubuntu0.24.04.3", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python3-rados", ver:"19.2.3-0ubuntu0.24.04.3", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python3-rbd", ver:"19.2.3-0ubuntu0.24.04.3", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python3-rgw", ver:"19.2.3-0ubuntu0.24.04.3", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"rados-objclass-dev", ver:"19.2.3-0ubuntu0.24.04.3", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"radosgw", ver:"19.2.3-0ubuntu0.24.04.3", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"rbd-fuse", ver:"19.2.3-0ubuntu0.24.04.3", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"rbd-mirror", ver:"19.2.3-0ubuntu0.24.04.3", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"rbd-nbd", ver:"19.2.3-0ubuntu0.24.04.3", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU25.10") {

  if(!isnull(res = isdpkgvuln(pkg:"ceph", ver:"19.2.3-0ubuntu1.25.10.3", rls:"UBUNTU25.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ceph-base", ver:"19.2.3-0ubuntu1.25.10.3", rls:"UBUNTU25.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ceph-common", ver:"19.2.3-0ubuntu1.25.10.3", rls:"UBUNTU25.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ceph-exporter", ver:"19.2.3-0ubuntu1.25.10.3", rls:"UBUNTU25.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ceph-fuse", ver:"19.2.3-0ubuntu1.25.10.3", rls:"UBUNTU25.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ceph-grafana-dashboards", ver:"19.2.3-0ubuntu1.25.10.3", rls:"UBUNTU25.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ceph-immutable-object-cache", ver:"19.2.3-0ubuntu1.25.10.3", rls:"UBUNTU25.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ceph-mds", ver:"19.2.3-0ubuntu1.25.10.3", rls:"UBUNTU25.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ceph-mgr", ver:"19.2.3-0ubuntu1.25.10.3", rls:"UBUNTU25.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ceph-mgr-cephadm", ver:"19.2.3-0ubuntu1.25.10.3", rls:"UBUNTU25.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ceph-mgr-dashboard", ver:"19.2.3-0ubuntu1.25.10.3", rls:"UBUNTU25.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ceph-mgr-diskprediction-local", ver:"19.2.3-0ubuntu1.25.10.3", rls:"UBUNTU25.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ceph-mgr-k8sevents", ver:"19.2.3-0ubuntu1.25.10.3", rls:"UBUNTU25.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ceph-mgr-modules-core", ver:"19.2.3-0ubuntu1.25.10.3", rls:"UBUNTU25.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ceph-mgr-rook", ver:"19.2.3-0ubuntu1.25.10.3", rls:"UBUNTU25.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ceph-mon", ver:"19.2.3-0ubuntu1.25.10.3", rls:"UBUNTU25.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ceph-osd", ver:"19.2.3-0ubuntu1.25.10.3", rls:"UBUNTU25.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ceph-prometheus-alerts", ver:"19.2.3-0ubuntu1.25.10.3", rls:"UBUNTU25.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ceph-resource-agents", ver:"19.2.3-0ubuntu1.25.10.3", rls:"UBUNTU25.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ceph-volume", ver:"19.2.3-0ubuntu1.25.10.3", rls:"UBUNTU25.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cephadm", ver:"19.2.3-0ubuntu1.25.10.3", rls:"UBUNTU25.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cephfs-mirror", ver:"19.2.3-0ubuntu1.25.10.3", rls:"UBUNTU25.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cephfs-shell", ver:"19.2.3-0ubuntu1.25.10.3", rls:"UBUNTU25.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crimson-osd", ver:"19.2.3-0ubuntu1.25.10.3", rls:"UBUNTU25.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libcephfs-dev", ver:"19.2.3-0ubuntu1.25.10.3", rls:"UBUNTU25.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libcephfs-java", ver:"19.2.3-0ubuntu1.25.10.3", rls:"UBUNTU25.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libcephfs-jni", ver:"19.2.3-0ubuntu1.25.10.3", rls:"UBUNTU25.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libcephfs2", ver:"19.2.3-0ubuntu1.25.10.3", rls:"UBUNTU25.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"librados-dev", ver:"19.2.3-0ubuntu1.25.10.3", rls:"UBUNTU25.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"librados2", ver:"19.2.3-0ubuntu1.25.10.3", rls:"UBUNTU25.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libradospp-dev", ver:"19.2.3-0ubuntu1.25.10.3", rls:"UBUNTU25.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libradosstriper-dev", ver:"19.2.3-0ubuntu1.25.10.3", rls:"UBUNTU25.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libradosstriper1", ver:"19.2.3-0ubuntu1.25.10.3", rls:"UBUNTU25.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"librbd-dev", ver:"19.2.3-0ubuntu1.25.10.3", rls:"UBUNTU25.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"librbd1", ver:"19.2.3-0ubuntu1.25.10.3", rls:"UBUNTU25.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"librgw-dev", ver:"19.2.3-0ubuntu1.25.10.3", rls:"UBUNTU25.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"librgw2", ver:"19.2.3-0ubuntu1.25.10.3", rls:"UBUNTU25.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libsqlite3-mod-ceph", ver:"19.2.3-0ubuntu1.25.10.3", rls:"UBUNTU25.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libsqlite3-mod-ceph-dev", ver:"19.2.3-0ubuntu1.25.10.3", rls:"UBUNTU25.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python3-ceph", ver:"19.2.3-0ubuntu1.25.10.3", rls:"UBUNTU25.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python3-ceph-argparse", ver:"19.2.3-0ubuntu1.25.10.3", rls:"UBUNTU25.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python3-ceph-common", ver:"19.2.3-0ubuntu1.25.10.3", rls:"UBUNTU25.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python3-cephfs", ver:"19.2.3-0ubuntu1.25.10.3", rls:"UBUNTU25.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python3-rados", ver:"19.2.3-0ubuntu1.25.10.3", rls:"UBUNTU25.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python3-rbd", ver:"19.2.3-0ubuntu1.25.10.3", rls:"UBUNTU25.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python3-rgw", ver:"19.2.3-0ubuntu1.25.10.3", rls:"UBUNTU25.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"rados-objclass-dev", ver:"19.2.3-0ubuntu1.25.10.3", rls:"UBUNTU25.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"radosgw", ver:"19.2.3-0ubuntu1.25.10.3", rls:"UBUNTU25.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"rbd-fuse", ver:"19.2.3-0ubuntu1.25.10.3", rls:"UBUNTU25.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"rbd-mirror", ver:"19.2.3-0ubuntu1.25.10.3", rls:"UBUNTU25.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"rbd-nbd", ver:"19.2.3-0ubuntu1.25.10.3", rls:"UBUNTU25.10"))) {
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
