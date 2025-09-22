# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.845403");
  script_cve_id("CVE-2019-20637", "CVE-2020-11653", "CVE-2021-36740", "CVE-2022-23959");
  script_tag(name:"creation_date", value:"2022-06-09 01:00:50 +0000 (Thu, 09 Jun 2022)");
  script_version("2024-02-02T05:06:10+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:10 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-02-07 18:16:51 +0000 (Mon, 07 Feb 2022)");

  script_name("Ubuntu: Security Advisory (USN-5474-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(18\.04\ LTS|20\.04\ LTS|21\.10|22\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-5474-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5474-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'varnish' package(s) announced via the USN-5474-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that Varnish Cache did not clear a pointer between the
handling of one client request and the next request within the same connection.
A remote attacker could possibly use this issue to obtain sensitive
information. (CVE-2019-20637)

It was discovered that Varnish Cache could have an assertion failure when a
TLS termination proxy uses PROXY version 2. A remote attacker could possibly
use this issue to restart the daemon and cause a performance loss.
(CVE-2020-11653)

It was discovered that Varnish Cache allowed request smuggling and VCL
authorization bypass via a large Content-Length header for a POST
request. A remote attacker could possibly use this issue to obtain sensitive
information. (CVE-2021-36740)

It was discovered that Varnish Cache allowed request smuggling for HTTP/1
connections. A remote attacker could possibly use this issue to obtain
sensitive information. (CVE-2022-23959)");

  script_tag(name:"affected", value:"'varnish' package(s) on Ubuntu 18.04, Ubuntu 20.04, Ubuntu 21.10, Ubuntu 22.04.");

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

if(release == "UBUNTU18.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"libvarnishapi1", ver:"5.2.1-1ubuntu0.1", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"varnish", ver:"5.2.1-1ubuntu0.1", rls:"UBUNTU18.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libvarnishapi2", ver:"6.2.1-2ubuntu0.1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"varnish", ver:"6.2.1-2ubuntu0.1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU21.10") {

  if(!isnull(res = isdpkgvuln(pkg:"libvarnishapi2", ver:"6.5.2-1ubuntu0.2", rls:"UBUNTU21.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"varnish", ver:"6.5.2-1ubuntu0.2", rls:"UBUNTU21.10"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libvarnishapi2", ver:"6.6.1-1ubuntu0.2", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"varnish", ver:"6.6.1-1ubuntu0.2", rls:"UBUNTU22.04 LTS"))) {
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
