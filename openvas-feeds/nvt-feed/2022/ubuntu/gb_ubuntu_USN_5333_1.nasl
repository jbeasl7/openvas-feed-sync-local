# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.845284");
  script_cve_id("CVE-2022-22719", "CVE-2022-22720", "CVE-2022-22721", "CVE-2022-23943");
  script_tag(name:"creation_date", value:"2022-03-18 02:00:24 +0000 (Fri, 18 Mar 2022)");
  script_version("2024-02-02T05:06:10+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:10 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-03-18 18:01:43 +0000 (Fri, 18 Mar 2022)");

  script_name("Ubuntu: Security Advisory (USN-5333-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(18\.04\ LTS|20\.04\ LTS|21\.10)");

  script_xref(name:"Advisory-ID", value:"USN-5333-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5333-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'apache2' package(s) announced via the USN-5333-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Chamal De Silva discovered that the Apache HTTP Server mod_lua module
incorrectly handled certain crafted request bodies. A remote attacker could
possibly use this issue to cause the server to crash, resulting in a denial
of service. (CVE-2022-22719)

James Kettle discovered that the Apache HTTP Server incorrectly closed
inbound connection when certain errors are encountered. A remote attacker
could possibly use this issue to perform an HTTP Request Smuggling attack.
(CVE-2022-22720)

It was discovered that the Apache HTTP Server incorrectly handled large
LimitXMLRequestBody settings on certain platforms. In certain
configurations, a remote attacker could use this issue to cause the server
to crash, resulting in a denial of service, or possibly execute arbitrary
code. (CVE-2022-22721)

Ronald Crane discovered that the Apache HTTP Server mod_sed module
incorrectly handled memory. A remote attacker could use this issue to cause
the server to crash, resulting in a denial of service, or possibly execute
arbitrary code. (CVE-2022-23943)");

  script_tag(name:"affected", value:"'apache2' package(s) on Ubuntu 18.04, Ubuntu 20.04, Ubuntu 21.10.");

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

  if(!isnull(res = isdpkgvuln(pkg:"apache2", ver:"2.4.29-1ubuntu4.22", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"apache2-bin", ver:"2.4.29-1ubuntu4.22", rls:"UBUNTU18.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"apache2", ver:"2.4.41-4ubuntu3.10", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"apache2-bin", ver:"2.4.41-4ubuntu3.10", rls:"UBUNTU20.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"apache2", ver:"2.4.48-3.1ubuntu3.3", rls:"UBUNTU21.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"apache2-bin", ver:"2.4.48-3.1ubuntu3.3", rls:"UBUNTU21.10"))) {
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
