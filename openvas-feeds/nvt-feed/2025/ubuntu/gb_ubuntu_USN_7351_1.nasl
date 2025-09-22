# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2025.7351.1");
  script_cve_id("CVE-2020-10688", "CVE-2020-1695", "CVE-2020-25633", "CVE-2021-20289", "CVE-2023-0482", "CVE-2024-9622");
  script_tag(name:"creation_date", value:"2025-03-14 04:04:05 +0000 (Fri, 14 Mar 2025)");
  script_version("2025-03-14T05:38:04+0000");
  script_tag(name:"last_modification", value:"2025-03-14 05:38:04 +0000 (Fri, 14 Mar 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-04-01 19:25:56 +0000 (Thu, 01 Apr 2021)");

  script_name("Ubuntu: Security Advisory (USN-7351-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(20\.04\ LTS|22\.04\ LTS|24\.04\ LTS|24\.10)");

  script_xref(name:"Advisory-ID", value:"USN-7351-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-7351-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'resteasy' package(s) announced via the USN-7351-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Nikos Papadopoulos discovered that RESTEasy improperly handled URL encoding
when certain errors occur. An attacker could possibly use this issue to
modify the app's behavior for other users through the network.
(CVE-2020-10688)

Mirko Selber discovered that RESTEasy improperly validated user input
during HTTP response construction. This issue could possibly allow an
attacker to cause a denial of service or execute arbitrary code.
(CVE-2020-1695)

It was discovered that RESTEasy unintentionally disclosed potentially
sensitive server information to users during the handling of certain
errors. (CVE-2020-25633)

It was discovered that RESTEasy unintentionally disclosed parts of its code
to users during the handling of certain errors. (CVE-2021-20289)

It was discovered that RESTEasy used improper permissions when creating
temporary files. An attacker could possibly use this issue to get access to
sensitive data. (CVE-2023-0482)

It was discovered that RESTEasy improperly handled certain HTTP requests
and could be forced into a state in which it can no longer accept incoming
connections. An attacker could possibly use this issue to cause a denial of
service. (CVE-2024-9622)");

  script_tag(name:"affected", value:"'resteasy' package(s) on Ubuntu 20.04, Ubuntu 22.04, Ubuntu 24.04, Ubuntu 24.10.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libresteasy-java", ver:"3.6.2-2ubuntu0.20.04.1~esm1", rls:"UBUNTU20.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libresteasy-java", ver:"3.6.2-2ubuntu0.22.04.1~esm1", rls:"UBUNTU22.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libresteasy-java", ver:"3.6.2-2ubuntu0.24.04.1~esm1", rls:"UBUNTU24.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libresteasy-java", ver:"3.6.2-2ubuntu0.24.10.1", rls:"UBUNTU24.10"))) {
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
