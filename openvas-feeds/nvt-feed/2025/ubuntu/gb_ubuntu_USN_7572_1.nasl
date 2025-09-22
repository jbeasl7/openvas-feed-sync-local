# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2025.7572.1");
  script_cve_id("CVE-2024-28243", "CVE-2024-28245", "CVE-2024-28246", "CVE-2025-23207");
  script_tag(name:"creation_date", value:"2025-06-19 04:09:12 +0000 (Thu, 19 Jun 2025)");
  script_version("2025-09-09T05:38:49+0000");
  script_tag(name:"last_modification", value:"2025-09-09 05:38:49 +0000 (Tue, 09 Sep 2025)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-09-08 21:17:11 +0000 (Mon, 08 Sep 2025)");

  script_name("Ubuntu: Security Advisory (USN-7572-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(22\.04\ LTS|24\.04\ LTS|24\.10|25\.04)");

  script_xref(name:"Advisory-ID", value:"USN-7572-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-7572-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'node-katex' package(s) announced via the USN-7572-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Juho Forsen discovered that KaTeX did not correctly handle certain
inputs, which could lead to an infinite loop. If a user or application
were tricked into opening a specially crafted file, an attacker could
possibly use this issue to cause a denial of service. This issue only
affected Ubuntu 22.04 LTS. (CVE-2024-28243)

Tobias S. Fink discovered that KaTeX did not correctly block certain
URL protocols. If a user or system were tricked into opening a specially
crafted file, an attacker could possibly use this issue to execute
arbitrary code. This issue only affected Ubuntu 22.04 LTS.
(CVE-2024-28246)

It was discovered that KaTeX did not correctly handle certain inputs. If
a user or system were tricked into opening a specially crafted file, an
attacker could possibly use this issue to execute arbitrary code. This
issue only affected Ubuntu 22.04 LTS. (CVE-2024-28245)

Sean Ng discovered that KaTeX did not correctly handle certain inputs. If
a user or system were tricked into opening a specially crafted file, an
attacker could possibly use this issue to execute arbitrary code.
(CVE-2025-23207)");

  script_tag(name:"affected", value:"'node-katex' package(s) on Ubuntu 22.04, Ubuntu 24.04, Ubuntu 24.10, Ubuntu 25.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"katex", ver:"0.13.11+~cs6.0.0-2ubuntu0.1~esm1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libjs-katex", ver:"0.13.11+~cs6.0.0-2ubuntu0.1~esm1", rls:"UBUNTU22.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"katex", ver:"0.16.10+~cs6.1.0-2ubuntu0.24.04.1~esm1", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libjs-katex", ver:"0.16.10+~cs6.1.0-2ubuntu0.24.04.1~esm1", rls:"UBUNTU24.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"katex", ver:"0.16.10+~cs6.1.0-2ubuntu0.24.10.1", rls:"UBUNTU24.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libjs-katex", ver:"0.16.10+~cs6.1.0-2ubuntu0.24.10.1", rls:"UBUNTU24.10"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU25.04") {

  if(!isnull(res = isdpkgvuln(pkg:"katex", ver:"0.16.10+~cs6.1.0-2ubuntu0.25.04.1", rls:"UBUNTU25.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libjs-katex", ver:"0.16.10+~cs6.1.0-2ubuntu0.25.04.1", rls:"UBUNTU25.04"))) {
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
