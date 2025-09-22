# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2025.7589.1");
  script_cve_id("CVE-2018-19490", "CVE-2018-19491", "CVE-2018-19492", "CVE-2020-25412", "CVE-2020-25559", "CVE-2020-25969", "CVE-2021-44917");
  script_tag(name:"creation_date", value:"2025-06-25 04:10:27 +0000 (Wed, 25 Jun 2025)");
  script_version("2025-06-25T05:41:02+0000");
  script_tag(name:"last_modification", value:"2025-06-25 05:41:02 +0000 (Wed, 25 Jun 2025)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-07-11 17:54:58 +0000 (Tue, 11 Jul 2023)");

  script_name("Ubuntu: Security Advisory (USN-7589-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(14\.04\ LTS|16\.04\ LTS|18\.04\ LTS|20\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-7589-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-7589-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'gnuplot' package(s) announced via the USN-7589-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Tim Blazytko, Cornelius Aschermann, Sergej Schumilo, and Nils Bars
discovered that Gnuplot had several memory-related issues. An
attacker could possibly use these issues to cause Gnuplot to
experience a buffer overflow, resulting in a denial of service or
arbitrary code execution. These issues only affected Ubuntu
14.04 LTS and Ubuntu 18.04 LTS. (CVE-2018-19490, CVE-2018-19491,
CVE-2018-19492)

It was discovered that Gnuplot could write out-of-bounds due to
the use of strncpy(). An attacker could possibly use this issue
to enable the execution of arbitrary code. This issue only
affected Ubuntu 20.04 LTS. (CVE-2020-25412)

It was discovered that Gnuplot incorrectly freed memory when
executing print_set_output(). An attacker could possibly use this
issue to enable the execution of arbitrary code. (CVE-2020-25559)

It was discovered that Gnuplot's plotrequest() function contained
a buffer overflow. An attacker could possibly use this issue to
cause Gnuplot to crash, resulting in a denial of service or
arbitrary code execution. (CVE-2020-25969)

It was discovered that Gnuplot's boundary3d() function could be
made to divide by zero. An attacker could possibly use this issue
to cause Gnuplot to crash, resulting in a denial of service.
(CVE-2021-44917)");

  script_tag(name:"affected", value:"'gnuplot' package(s) on Ubuntu 14.04, Ubuntu 16.04, Ubuntu 18.04, Ubuntu 20.04.");

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

if(release == "UBUNTU14.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"gnuplot", ver:"4.6.4-2ubuntu0.1~esm1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"gnuplot-nox", ver:"4.6.4-2ubuntu0.1~esm1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"gnuplot-qt", ver:"4.6.4-2ubuntu0.1~esm1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"gnuplot-x11", ver:"4.6.4-2ubuntu0.1~esm1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU16.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"gnuplot", ver:"4.6.6-3ubuntu0.1+esm1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"gnuplot-data", ver:"4.6.6-3ubuntu0.1+esm1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"gnuplot-nox", ver:"4.6.6-3ubuntu0.1+esm1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"gnuplot-qt", ver:"4.6.6-3ubuntu0.1+esm1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"gnuplot-tex", ver:"4.6.6-3ubuntu0.1+esm1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"gnuplot-x11", ver:"4.6.6-3ubuntu0.1+esm1", rls:"UBUNTU16.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"gnuplot", ver:"5.2.2+dfsg1-2ubuntu1+esm1", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"gnuplot-data", ver:"5.2.2+dfsg1-2ubuntu1+esm1", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"gnuplot-nox", ver:"5.2.2+dfsg1-2ubuntu1+esm1", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"gnuplot-qt", ver:"5.2.2+dfsg1-2ubuntu1+esm1", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"gnuplot-x11", ver:"5.2.2+dfsg1-2ubuntu1+esm1", rls:"UBUNTU18.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"gnuplot", ver:"5.2.8+dfsg1-2ubuntu0.1~esm1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"gnuplot-data", ver:"5.2.8+dfsg1-2ubuntu0.1~esm1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"gnuplot-nox", ver:"5.2.8+dfsg1-2ubuntu0.1~esm1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"gnuplot-qt", ver:"5.2.8+dfsg1-2ubuntu0.1~esm1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"gnuplot-x11", ver:"5.2.8+dfsg1-2ubuntu0.1~esm1", rls:"UBUNTU20.04 LTS"))) {
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
