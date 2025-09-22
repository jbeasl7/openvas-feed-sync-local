# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2025.7343.2");
  script_cve_id("CVE-2024-56201", "CVE-2024-56326", "CVE-2025-27516");
  script_tag(name:"creation_date", value:"2025-03-13 04:04:12 +0000 (Thu, 13 Mar 2025)");
  script_version("2025-03-13T05:38:41+0000");
  script_tag(name:"last_modification", value:"2025-03-13 05:38:41 +0000 (Thu, 13 Mar 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Ubuntu: Security Advisory (USN-7343-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(18\.04\ LTS|20\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-7343-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-7343-2");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/2102129");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'jinja2' package(s) announced via the USN-7343-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-7343-1 fixed vulnerabilities in Jinja2. The update introduced a
regression when attempting to import Jinja2 on Ubuntu 18.04 LTS and
Ubuntu 20.04 LTS. This update fixes the problem.

We apologize for the inconvenience.

Original advisory details:

Rafal Krupinski discovered that Jinja2 did not properly restrict
the execution of code in situations where templates are used maliciously.
An attacker with control over a template's filename and content could
potentially use this issue to enable the execution of arbitrary code.
This issue only affected Ubuntu 14.04 LTS and Ubuntu 16.04 LTS.
(CVE-2024-56201)

It was discovered that Jinja2 sandboxed environments could be escaped
through a call to a string format method. An attacker could possibly use
this issue to enable the execution of arbitrary code. This issue only
affected Ubuntu 14.04 LTS and Ubuntu 16.04 LTS. (CVE-2024-56326)

It was discovered that Jinja2 sandboxed environments could be escaped
through the malicious use of certain filters. An attacker could possibly
use this issue to enable the execution of arbitrary code. (CVE-2025-27516)");

  script_tag(name:"affected", value:"'jinja2' package(s) on Ubuntu 18.04, Ubuntu 20.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"python-jinja2", ver:"2.10-1ubuntu0.18.04.1+esm5", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python3-jinja2", ver:"2.10-1ubuntu0.18.04.1+esm5", rls:"UBUNTU18.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"python-jinja2", ver:"2.10.1-2ubuntu0.6", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python3-jinja2", ver:"2.10.1-2ubuntu0.6", rls:"UBUNTU20.04 LTS"))) {
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
