# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.844694");
  script_cve_id("CVE-2018-14036", "CVE-2020-16126", "CVE-2020-16127");
  script_tag(name:"creation_date", value:"2020-11-04 04:00:41 +0000 (Wed, 04 Nov 2020)");
  script_version("2024-02-02T05:06:07+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:07 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-09-06 16:16:06 +0000 (Thu, 06 Sep 2018)");

  script_name("Ubuntu: Security Advisory (USN-4616-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(16\.04\ LTS|18\.04\ LTS|20\.04\ LTS|20\.10)");

  script_xref(name:"Advisory-ID", value:"USN-4616-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4616-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'accountsservice' package(s) announced via the USN-4616-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Kevin Backhouse discovered that AccountsService incorrectly dropped
privileges. A local user could possibly use this issue to cause
AccountsService to crash or hang, resulting in a denial of service.
(CVE-2020-16126)

Kevin Backhouse discovered that AccountsService incorrectly handled reading
.pam_environment files. A local user could possibly use this issue to cause
AccountsService to crash or hang, resulting in a denial of service. This
issue only affected Ubuntu 20.04 LTS and Ubuntu 20.10. (CVE-2020-16127)

Matthias Gerstner discovered that AccountsService incorrectly handled
certain path checks. A local attacker could possibly use this issue to
read arbitrary files. This issue only affected Ubuntu 16.04 LTS and Ubuntu
18.04 LTS. (CVE-2018-14036)");

  script_tag(name:"affected", value:"'accountsservice' package(s) on Ubuntu 16.04, Ubuntu 18.04, Ubuntu 20.04, Ubuntu 20.10.");

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

  if(!isnull(res = isdpkgvuln(pkg:"accountsservice", ver:"0.6.40-2ubuntu11.6", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libaccountsservice0", ver:"0.6.40-2ubuntu11.6", rls:"UBUNTU16.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"accountsservice", ver:"0.6.45-1ubuntu1.3", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libaccountsservice0", ver:"0.6.45-1ubuntu1.3", rls:"UBUNTU18.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"accountsservice", ver:"0.6.55-0ubuntu12~20.04.4", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libaccountsservice0", ver:"0.6.55-0ubuntu12~20.04.4", rls:"UBUNTU20.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"accountsservice", ver:"0.6.55-0ubuntu13.2", rls:"UBUNTU20.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libaccountsservice0", ver:"0.6.55-0ubuntu13.2", rls:"UBUNTU20.10"))) {
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
