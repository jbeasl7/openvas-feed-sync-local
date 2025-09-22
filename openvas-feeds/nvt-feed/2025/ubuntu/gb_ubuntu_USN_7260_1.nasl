# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2025.7260.1");
  script_cve_id("CVE-2023-37476", "CVE-2023-41886", "CVE-2023-41887", "CVE-2024-23833", "CVE-2024-47878", "CVE-2024-47879", "CVE-2024-47880", "CVE-2024-47881", "CVE-2024-47882", "CVE-2024-49760");
  script_tag(name:"creation_date", value:"2025-02-10 08:41:36 +0000 (Mon, 10 Feb 2025)");
  script_version("2025-02-11T05:38:07+0000");
  script_tag(name:"last_modification", value:"2025-02-11 05:38:07 +0000 (Tue, 11 Feb 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-09-20 19:20:19 +0000 (Wed, 20 Sep 2023)");

  script_name("Ubuntu: Security Advisory (USN-7260-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(22\.04\ LTS|24\.04\ LTS|24\.10)");

  script_xref(name:"Advisory-ID", value:"USN-7260-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-7260-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openrefine' package(s) announced via the USN-7260-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that OpenRefine did not properly handle opening tar
files. If a user or application were tricked into opening a crafted tar
file, an attacker could possibly use this issue to execute arbitrary code.
This issue only affected Ubuntu 22.04 LTS. (CVE-2023-37476)

It was discovered that OpenRefine incorrectly handled file permissions and
user authentication. An unauthenticated attacker could possibly use this
issue to leak sensitive information or execute arbitrary code. This issue
only affected Ubuntu 22.04 LTS. (CVE-2023-41886, CVE-2023-41887)

It was discovered that OpenRefine did not properly disallow database
settings to be modified when queried. An attacker could possibly use this
issue to leak sensitive information. This issue only affected
Ubuntu 22.04 LTS and Ubuntu 24.04 LTS. (CVE-2024-23833)

It was discovered that OpenRefine did not properly sanitize the GET
parameter for authorized commands, leading to a cross site scripting
vulnerability. An attacker could possibly use this issue to execute
arbitrary code. (CVE-2024-47878)

It was discovered that OpenRefine did not properly prevent cross-site
request forgery when running the preview-expression command. If a user or
application were tricked into opening a specially crafted webpage, an
attacker could possibly use this issue to execute arbitrary code.
(CVE-2024-47879)

It was discovered that OpenRefine did not properly handle HTTP headers.
An attacker could possibly use this issue to execute arbitrary code.
(CVE-2024-47880)

It was discovered that OpenRefine incorrectly handled database extensions.
An attacker could possibly use this issue to execute arbitrary code.
(CVE-2024-47881)

It was discovered that OpenRefine did not properly escape HTML tags in
exception messages, which could enable code injection. If a user or
application were tricked into opening a malicious file, an attacker could
use this issue to execute arbitrary code. (CVE-2024-47882)

It was discovered that OpenRefine did not correctly handle paths when
executing the load-language command. An attacker could possibly use this
issue to leak sensitive information. (CVE-2024-49760)");

  script_tag(name:"affected", value:"'openrefine' package(s) on Ubuntu 22.04, Ubuntu 24.04, Ubuntu 24.10.");

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

if(release == "UBUNTU22.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"openrefine", ver:"3.5.2-1ubuntu0.1~esm1", rls:"UBUNTU22.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"openrefine", ver:"3.7.7-1ubuntu0.1~esm1", rls:"UBUNTU24.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"openrefine", ver:"3.7.8-1ubuntu0.1", rls:"UBUNTU24.10"))) {
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
