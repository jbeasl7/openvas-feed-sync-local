# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.844845");
  script_cve_id("CVE-2019-14834", "CVE-2020-25681", "CVE-2020-25682", "CVE-2020-25683", "CVE-2020-25684", "CVE-2020-25685", "CVE-2020-25686", "CVE-2020-25687");
  script_tag(name:"creation_date", value:"2021-02-25 04:00:26 +0000 (Thu, 25 Feb 2021)");
  script_version("2024-02-02T05:06:08+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:08 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"8.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-01-28 20:02:57 +0000 (Thu, 28 Jan 2021)");

  script_name("Ubuntu: Security Advisory (USN-4698-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(16\.04\ LTS|18\.04\ LTS|20\.04\ LTS|20\.10)");

  script_xref(name:"Advisory-ID", value:"USN-4698-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4698-2");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/1916462");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'dnsmasq' package(s) announced via the USN-4698-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-4698-1 fixed vulnerabilities in Dnsmasq. The updates introduced
regressions in certain environments related to issues with multiple
queries, and issues with retries. This update fixes the problem.

Original advisory details:

 Moshe Kol and Shlomi Oberman discovered that Dnsmasq incorrectly handled
 memory when sorting RRsets. A remote attacker could use this issue to cause
 Dnsmasq to hang, resulting in a denial of service, or possibly execute
 arbitrary code. (CVE-2020-25681, CVE-2020-25687)

 Moshe Kol and Shlomi Oberman discovered that Dnsmasq incorrectly handled
 extracting certain names. A remote attacker could use this issue to cause
 Dnsmasq to hang, resulting in a denial of service, or possibly execute
 arbitrary code. (CVE-2020-25682, CVE-2020-25683)

 Moshe Kol and Shlomi Oberman discovered that Dnsmasq incorrectly
 implemented address/port checks. A remote attacker could use this issue to
 perform a cache poisoning attack. (CVE-2020-25684)

 Moshe Kol and Shlomi Oberman discovered that Dnsmasq incorrectly
 implemented query resource name checks. A remote attacker could use this
 issue to perform a cache poisoning attack. (CVE-2020-25685)

 Moshe Kol and Shlomi Oberman discovered that Dnsmasq incorrectly handled
 multiple query requests for the same resource name. A remote attacker could
 use this issue to perform a cache poisoning attack. (CVE-2020-25686)

 It was discovered that Dnsmasq incorrectly handled memory during DHCP
 response creation. A remote attacker could possibly use this issue to
 cause Dnsmasq to consume resources, leading to a denial of service. This
 issue only affected Ubuntu 16.04 LTS, Ubuntu 18.04 LTS, and Ubuntu 20.04
 LTS. (CVE-2019-14834)");

  script_tag(name:"affected", value:"'dnsmasq' package(s) on Ubuntu 16.04, Ubuntu 18.04, Ubuntu 20.04, Ubuntu 20.10.");

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

if(release == "UBUNTU16.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"dnsmasq", ver:"2.75-1ubuntu0.16.04.8", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dnsmasq-base", ver:"2.75-1ubuntu0.16.04.8", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dnsmasq-utils", ver:"2.75-1ubuntu0.16.04.8", rls:"UBUNTU16.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"dnsmasq", ver:"2.79-1ubuntu0.3", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dnsmasq-base", ver:"2.79-1ubuntu0.3", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dnsmasq-utils", ver:"2.79-1ubuntu0.3", rls:"UBUNTU18.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"dnsmasq", ver:"2.80-1.1ubuntu1.3", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dnsmasq-base", ver:"2.80-1.1ubuntu1.3", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dnsmasq-utils", ver:"2.80-1.1ubuntu1.3", rls:"UBUNTU20.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"dnsmasq", ver:"2.82-1ubuntu1.2", rls:"UBUNTU20.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dnsmasq-base", ver:"2.82-1ubuntu1.2", rls:"UBUNTU20.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dnsmasq-utils", ver:"2.82-1ubuntu1.2", rls:"UBUNTU20.10"))) {
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
