# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.844993");
  script_cve_id("CVE-2020-25678", "CVE-2020-27781", "CVE-2020-27839", "CVE-2021-20288", "CVE-2021-3509", "CVE-2021-3524", "CVE-2021-3531");
  script_tag(name:"creation_date", value:"2021-06-26 03:00:53 +0000 (Sat, 26 Jun 2021)");
  script_version("2024-02-02T05:06:08+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:08 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-04-22 17:31:37 +0000 (Thu, 22 Apr 2021)");

  script_name("Ubuntu: Security Advisory (USN-4998-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(20\.04\ LTS|20\.10)");

  script_xref(name:"Advisory-ID", value:"USN-4998-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4998-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ceph' package(s) announced via the USN-4998-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that in some situations Ceph logged passwords from the
mgr module in clear text. An attacker could use this to expose sensitive
information. (CVE-2020-25678)

Goutham Pacha Ravi, Jahson Babel, and John Garbutt discovered that user
credentials in Ceph could be manipulated in certain environments. An
attacker could use this to gain unintended access. (CVE-2020-27781)

It was discovered that the Ceph dashboard was susceptible to a cross-site
scripting attack. An attacker could use this to expose sensitive
information or gain unintended access. (CVE-2020-27839)

It was discovered that Ceph contained an authentication flaw, leading to
key reuse. An attacker could use this to cause a denial of service or
possibly impersonate another user. (CVE-2021-20288)

Sergey Bobrov discovered that the Ceph dashboard was susceptible to a
cross-site scripting attack. An attacker could use this to expose sensitive
information or gain unintended access. (CVE-2021-3509)

Sergey Bobrov discovered that Ceph's RadosGW (Ceph Object Gateway) allowed
the injection of HTTP headers in responses to CORS requests. An attacker
could use this to violate system integrity. (CVE-2021-3524)

It was discovered that Ceph's RadosGW (Ceph Object Gateway) did not
properly handle GET requests for swift URLs in some situations, leading to
an application crash. An attacker could use this to cause a denial of
service. (CVE-2021-3531)");

  script_tag(name:"affected", value:"'ceph' package(s) on Ubuntu 20.04, Ubuntu 20.10.");

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

if(release == "UBUNTU20.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"ceph", ver:"15.2.12-0ubuntu0.20.04.1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ceph-base", ver:"15.2.12-0ubuntu0.20.04.1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ceph-common", ver:"15.2.12-0ubuntu0.20.04.1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ceph-mgr", ver:"15.2.12-0ubuntu0.20.04.1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ceph-mgr-cephadm", ver:"15.2.12-0ubuntu0.20.04.1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ceph-mgr-dashboard", ver:"15.2.12-0ubuntu0.20.04.1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ceph-mgr-diskprediction-cloud", ver:"15.2.12-0ubuntu0.20.04.1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ceph-mgr-diskprediction-local", ver:"15.2.12-0ubuntu0.20.04.1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ceph-mgr-k8sevents", ver:"15.2.12-0ubuntu0.20.04.1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ceph-mgr-modules-core", ver:"15.2.12-0ubuntu0.20.04.1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ceph-mgr-rook", ver:"15.2.12-0ubuntu0.20.04.1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cephadm", ver:"15.2.12-0ubuntu0.20.04.1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"radosgw", ver:"15.2.12-0ubuntu0.20.04.1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU20.10") {

  if(!isnull(res = isdpkgvuln(pkg:"ceph", ver:"15.2.12-0ubuntu0.20.10.1", rls:"UBUNTU20.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ceph-base", ver:"15.2.12-0ubuntu0.20.10.1", rls:"UBUNTU20.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ceph-common", ver:"15.2.12-0ubuntu0.20.10.1", rls:"UBUNTU20.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ceph-mgr", ver:"15.2.12-0ubuntu0.20.10.1", rls:"UBUNTU20.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ceph-mgr-cephadm", ver:"15.2.12-0ubuntu0.20.10.1", rls:"UBUNTU20.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ceph-mgr-dashboard", ver:"15.2.12-0ubuntu0.20.10.1", rls:"UBUNTU20.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ceph-mgr-diskprediction-cloud", ver:"15.2.12-0ubuntu0.20.10.1", rls:"UBUNTU20.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ceph-mgr-diskprediction-local", ver:"15.2.12-0ubuntu0.20.10.1", rls:"UBUNTU20.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ceph-mgr-k8sevents", ver:"15.2.12-0ubuntu0.20.10.1", rls:"UBUNTU20.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ceph-mgr-modules-core", ver:"15.2.12-0ubuntu0.20.10.1", rls:"UBUNTU20.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ceph-mgr-rook", ver:"15.2.12-0ubuntu0.20.10.1", rls:"UBUNTU20.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cephadm", ver:"15.2.12-0ubuntu0.20.10.1", rls:"UBUNTU20.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"radosgw", ver:"15.2.12-0ubuntu0.20.10.1", rls:"UBUNTU20.10"))) {
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
