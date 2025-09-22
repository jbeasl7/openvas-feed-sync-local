# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2024.6891.1");
  script_cve_id("CVE-2015-20107", "CVE-2018-1060", "CVE-2018-1061", "CVE-2018-14647", "CVE-2018-20406", "CVE-2018-20852", "CVE-2019-10160", "CVE-2019-16056", "CVE-2019-16935", "CVE-2019-17514", "CVE-2019-18348", "CVE-2019-20907", "CVE-2019-5010", "CVE-2019-9636", "CVE-2019-9674", "CVE-2019-9740", "CVE-2019-9947", "CVE-2019-9948", "CVE-2020-14422", "CVE-2020-26116", "CVE-2020-27619", "CVE-2020-8492", "CVE-2021-29921", "CVE-2021-3177", "CVE-2021-3426", "CVE-2021-3733", "CVE-2021-3737", "CVE-2021-4189", "CVE-2022-0391", "CVE-2022-42919", "CVE-2022-45061", "CVE-2022-48560", "CVE-2022-48564", "CVE-2022-48565", "CVE-2022-48566", "CVE-2023-24329", "CVE-2023-40217", "CVE-2023-41105", "CVE-2023-6507", "CVE-2023-6597", "CVE-2024-0450");
  script_tag(name:"creation_date", value:"2024-07-12 04:07:54 +0000 (Fri, 12 Jul 2024)");
  script_version("2024-07-12T05:05:45+0000");
  script_tag(name:"last_modification", value:"2024-07-12 05:05:45 +0000 (Fri, 12 Jul 2024)");
  script_tag(name:"cvss_base", value:"8.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:C/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-09-01 13:36:41 +0000 (Fri, 01 Sep 2023)");

  script_name("Ubuntu: Security Advisory (USN-6891-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(14\.04\ LTS|16\.04\ LTS|18\.04\ LTS|20\.04\ LTS|22\.04\ LTS|23\.10)");

  script_xref(name:"Advisory-ID", value:"USN-6891-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6891-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python3.5, python3.6, python3.7, python3.8, python3.9, python3.10, python3.11, python3.12' package(s) announced via the USN-6891-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that Python incorrectly handled certain inputs.
An attacker could possibly use this issue to execute arbitrary code.
This issue only affected Ubuntu 14.04 LTS and Ubuntu 18.04 LTS.
(CVE-2015-20107)

It was discovered that Python incorrectly used regular expressions
vulnerable to catastrophic backtracking. A remote attacker could possibly
use this issue to cause a denial of service. This issue only affected
Ubuntu 14.04 LTS. (CVE-2018-1060, CVE-2018-1061)

It was discovered that Python failed to initialize Expat's hash salt. A
remote attacker could possibly use this issue to cause hash collisions,
leading to a denial of service. This issue only affected Ubuntu 14.04 LTS.
(CVE-2018-14647)

It was discovered that Python incorrectly handled certain pickle files. An
attacker could possibly use this issue to consume memory, leading to a
denial of service. This issue only affected Ubuntu 14.04 LTS.
(CVE-2018-20406)

It was discovered that Python incorrectly validated the domain when
handling cookies. An attacker could possibly trick Python into sending
cookies to the wrong domain. This issue only affected Ubuntu 14.04 LTS.
(CVE-2018-20852)

Jonathan Birch and Panayiotis Panayiotou discovered that Python incorrectly
handled Unicode encoding during NFKC normalization. An attacker could
possibly use this issue to obtain sensitive information. This issue only
affected Ubuntu 14.04 LTS. (CVE-2019-9636, CVE-2019-10160)

It was discovered that Python incorrectly parsed certain email addresses. A
remote attacker could possibly use this issue to trick Python applications
into accepting email addresses that should be denied. This issue only
affected Ubuntu 14.04 LTS. (CVE-2019-16056)

It was discovered that the Python documentation XML-RPC server incorrectly
handled certain fields. A remote attacker could use this issue to execute a
cross-site scripting (XSS) attack. This issue only affected Ubuntu 14.04
LTS. (CVE-2019-16935)

It was discovered that Python documentation had a misleading information.
A security issue could be possibly caused by wrong assumptions of this
information. This issue only affected Ubuntu 14.04 LTS and Ubuntu 18.04
LTS. (CVE-2019-17514)

It was discovered that Python incorrectly stripped certain characters from
requests. A remote attacker could use this issue to perform CRLF injection.
This issue only affected Ubuntu 14.04 LTS and Ubuntu 18.04 LTS.
(CVE-2019-18348)

It was discovered that Python incorrectly handled certain TAR archives.
An attacker could possibly use this issue to cause a denial of service.
This issue only affected Ubuntu 14.04 LTS and Ubuntu 18.04 LTS.
(CVE-2019-20907)

Colin Read and Nicolas Edet discovered that Python incorrectly handled
parsing certain X509 certificates. An attacker could possibly use this
issue to cause Python to crash, resulting in a denial of service. This
issue only affected Ubuntu 14.04 LTS. ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'python3.5, python3.6, python3.7, python3.8, python3.9, python3.10, python3.11, python3.12' package(s) on Ubuntu 14.04, Ubuntu 16.04, Ubuntu 18.04, Ubuntu 20.04, Ubuntu 22.04, Ubuntu 23.10.");

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

  if(!isnull(res = isdpkgvuln(pkg:"python3.5", ver:"3.5.2-2ubuntu0~16.04.4~14.04.1+esm1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python3.5-minimal", ver:"3.5.2-2ubuntu0~16.04.4~14.04.1+esm1", rls:"UBUNTU14.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"python3.5", ver:"3.5.2-2ubuntu0~16.04.13+esm13", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python3.5-minimal", ver:"3.5.2-2ubuntu0~16.04.13+esm13", rls:"UBUNTU16.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"python3.6", ver:"3.6.9-1~18.04ubuntu1.13+esm2", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python3.6-minimal", ver:"3.6.9-1~18.04ubuntu1.13+esm2", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python3.7", ver:"3.7.5-2ubuntu1~18.04.2+esm3", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python3.7-minimal", ver:"3.7.5-2ubuntu1~18.04.2+esm3", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python3.8", ver:"3.8.0-3ubuntu1~18.04.2+esm2", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python3.8-minimal", ver:"3.8.0-3ubuntu1~18.04.2+esm2", rls:"UBUNTU18.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"python3.8", ver:"3.8.10-0ubuntu1~20.04.10", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python3.8-minimal", ver:"3.8.10-0ubuntu1~20.04.10", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python3.9", ver:"3.9.5-3ubuntu0~20.04.1+esm2", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python3.9-minimal", ver:"3.9.5-3ubuntu0~20.04.1+esm2", rls:"UBUNTU20.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"python3.10", ver:"3.10.12-1~22.04.4", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python3.10-minimal", ver:"3.10.12-1~22.04.4", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python3.11", ver:"3.11.0~rc1-1~22.04.1~esm1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python3.11-minimal", ver:"3.11.0~rc1-1~22.04.1~esm1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU23.10") {

  if(!isnull(res = isdpkgvuln(pkg:"python3.11", ver:"3.11.6-3ubuntu0.1", rls:"UBUNTU23.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python3.11-minimal", ver:"3.11.6-3ubuntu0.1", rls:"UBUNTU23.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python3.12", ver:"3.12.0-1ubuntu0.1", rls:"UBUNTU23.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python3.12-minimal", ver:"3.12.0-1ubuntu0.1", rls:"UBUNTU23.10"))) {
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
