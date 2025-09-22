# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2025.7418.1");
  script_cve_id("CVE-2024-35176", "CVE-2024-39908", "CVE-2024-41123", "CVE-2024-43398", "CVE-2025-25186", "CVE-2025-27219", "CVE-2025-27220", "CVE-2025-27221");
  script_tag(name:"creation_date", value:"2025-04-08 04:04:14 +0000 (Tue, 08 Apr 2025)");
  script_version("2025-05-01T05:40:03+0000");
  script_tag(name:"last_modification", value:"2025-05-01 05:40:03 +0000 (Thu, 01 May 2025)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-03-05 14:58:14 +0000 (Wed, 05 Mar 2025)");

  script_name("Ubuntu: Security Advisory (USN-7418-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(20\.04\ LTS|22\.04\ LTS|24\.04\ LTS|24\.10)");

  script_xref(name:"Advisory-ID", value:"USN-7418-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-7418-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ruby2.7, ruby3.0, ruby3.2, ruby3.3' package(s) announced via the USN-7418-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that Ruby incorrectly handled parsing of an XML document
that has specific XML characters in an attribute value using REXML gem. An
attacker could use this issue to cause Ruby to crash, resulting in a
denial of service. This issue only affected in Ubuntu 22.04 LTS, Ubuntu
24.04 LTS, and Ubuntu 24.10. (CVE-2024-35176, CVE-2024-39908,
CVE-2024-41123, CVE-2024-43398)

It was discovered that Ruby incorrectly handled expanding ranges in the
net-imap response parser. If a user or automated system were tricked into
connecting to a malicious IMAP server, a remote attacker could possibly use
this issue to consume memory, leading to a denial of service. This issue
only affected Ubuntu 24.04 LTS, and Ubuntu 24.10. (CVE-2025-25186)

It was discovered that the Ruby CGI gem incorrectly handled parsing certain
cookies. A remote attacker could possibly use this issue to consume
resources, leading to a denial of service. (CVE-2025-27219)

It was discovered that the Ruby CGI gem incorrectly handled parsing certain
regular expressions. A remote attacker could possibly use this issue to
consume resources, leading to a denial of service. (CVE-2025-27220)

It was discovered that the Ruby URI gem incorrectly handled certain URI
handling methods. A remote attacker could possibly use this issue to leak
authentication credentials. (CVE-2025-27221)");

  script_tag(name:"affected", value:"'ruby2.7, ruby3.0, ruby3.2, ruby3.3' package(s) on Ubuntu 20.04, Ubuntu 22.04, Ubuntu 24.04, Ubuntu 24.10.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libruby2.7", ver:"2.7.0-5ubuntu1.18", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ruby2.7", ver:"2.7.0-5ubuntu1.18", rls:"UBUNTU20.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libruby3.0", ver:"3.0.2-7ubuntu2.10", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ruby3.0", ver:"3.0.2-7ubuntu2.10", rls:"UBUNTU22.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libruby3.2", ver:"3.2.3-1ubuntu0.24.04.5", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ruby3.2", ver:"3.2.3-1ubuntu0.24.04.5", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU24.10") {

  if(!isnull(res = isdpkgvuln(pkg:"libruby3.3", ver:"3.3.4-2ubuntu5.2", rls:"UBUNTU24.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ruby3.3", ver:"3.3.4-2ubuntu5.2", rls:"UBUNTU24.10"))) {
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
