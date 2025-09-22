# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.841598");
  script_cve_id("CVE-2013-2256", "CVE-2013-4179", "CVE-2013-4185", "CVE-2013-4261", "CVE-2013-4278");
  script_tag(name:"creation_date", value:"2013-10-29 10:51:58 +0000 (Tue, 29 Oct 2013)");
  script_version("2024-02-02T05:06:04+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:04 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:P/I:P/A:P");

  script_name("Ubuntu: Security Advisory (USN-2000-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(12\.04\ LTS|12\.10|13\.04)");

  script_xref(name:"Advisory-ID", value:"USN-2000-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2000-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'nova' package(s) announced via the USN-2000-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that Nova did not properly enforce the is_public property
when determining flavor access. An authenticated attacker could exploit
this to obtain sensitive information in private flavors. This issue only
affected Ubuntu 12.10 and 13.10. (CVE-2013-2256, CVE-2013-4278)

Grant Murphy discovered that Nova would allow XML entity processing. A
remote unauthenticated attacker could exploit this using the Nova API to
cause a denial of service via resource exhaustion. This issue only
affected Ubuntu 13.10. (CVE-2013-4179)

Vishvananda Ishaya discovered that Nova inefficiently handled network
security group updates when Nova was configured to use nova-network. An
authenticated attacker could exploit this to cause a denial of service.
(CVE-2013-4185)

Jaroslav Henner discovered that Nova did not properly handle certain inputs
to the instance console when Nova was configured to use Apache Qpid. An
authenticated attacker could exploit this to cause a denial of service on
the compute node running the instance. By default, Ubuntu uses RabbitMQ
instead of Qpid. (CVE-2013-4261)");

  script_tag(name:"affected", value:"'nova' package(s) on Ubuntu 12.04, Ubuntu 12.10, Ubuntu 13.04.");

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

if(release == "UBUNTU12.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"python-nova", ver:"2012.1.3+stable-20130423-e52e6912-0ubuntu1.2", rls:"UBUNTU12.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU12.10") {

  if(!isnull(res = isdpkgvuln(pkg:"python-nova", ver:"2012.2.4-0ubuntu3.1", rls:"UBUNTU12.10"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU13.04") {

  if(!isnull(res = isdpkgvuln(pkg:"python-nova", ver:"1:2013.1.3-0ubuntu1.1", rls:"UBUNTU13.04"))) {
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
