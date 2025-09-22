# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.840822");
  script_cve_id("CVE-2011-1091", "CVE-2011-3184", "CVE-2011-3594");
  script_tag(name:"creation_date", value:"2011-11-25 06:33:41 +0000 (Fri, 25 Nov 2011)");
  script_version("2024-02-02T05:06:04+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:04 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");

  script_name("Ubuntu: Security Advisory (USN-1273-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(10\.04\ LTS|10\.10|11\.04)");

  script_xref(name:"Advisory-ID", value:"USN-1273-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1273-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'pidgin' package(s) announced via the USN-1273-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Marius Wachtler discovered that Pidgin incorrectly handled malformed YMSG
messages in the Yahoo! protocol handler. A remote attacker could send a
specially crafted message and cause Pidgin to crash, leading to a denial
of service. This issue only affected Ubuntu 10.04 LTS and 10.10.
(CVE-2011-1091)

Marius Wachtler discovered that Pidgin incorrectly handled HTTP 100
responses in the MSN protocol handler. A remote attacker could send a
specially crafted message and cause Pidgin to crash, leading to a denial
of service. (CVE-2011-3184)

Diego Bauche Madero discovered that Pidgin incorrectly handled UTF-8
sequences in the SILC protocol handler. A remote attacker could send a
specially crafted message and cause Pidgin to crash, leading to a denial
of service. (CVE-2011-3594)");

  script_tag(name:"affected", value:"'pidgin' package(s) on Ubuntu 10.04, Ubuntu 10.10, Ubuntu 11.04.");

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

if(release == "UBUNTU10.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"pidgin", ver:"1:2.6.6-1ubuntu4.4", rls:"UBUNTU10.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU10.10") {

  if(!isnull(res = isdpkgvuln(pkg:"pidgin", ver:"1:2.7.3-1ubuntu3.3", rls:"UBUNTU10.10"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU11.04") {

  if(!isnull(res = isdpkgvuln(pkg:"pidgin", ver:"1:2.7.11-1ubuntu2.1", rls:"UBUNTU11.04"))) {
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
