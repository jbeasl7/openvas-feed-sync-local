# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.844686");
  script_cve_id("CVE-2018-1000528", "CVE-2019-11187", "CVE-2019-14466");
  script_tag(name:"creation_date", value:"2020-10-29 04:00:28 +0000 (Thu, 29 Oct 2020)");
  script_version("2024-02-02T05:06:07+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:07 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-08-28 19:10:59 +0000 (Wed, 28 Aug 2019)");

  script_name("Ubuntu: Security Advisory (USN-4609-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU16\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-4609-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4609-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'gosa' package(s) announced via the USN-4609-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Fabian Henneke discovered that GOsa incorrectly handled client cookies. An
authenticated user could exploit this with a crafted cookie to perform
file deletions in the context of the user account that runs the web
server. (CVE-2019-14466)

It was discovered that GOsa incorrectly handled user access control. A
remote attacker could use this issue to log into any account with a
username containing the word 'success'. (CVE-2019-11187)

Fabian Henneke discovered that GOsa was vulnerable to cross-site scripting
attacks via the change password form. A remote attacker could use this
flaw to run arbitrary web scripts. (CVE-2018-1000528)");

  script_tag(name:"affected", value:"'gosa' package(s) on Ubuntu 16.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"gosa", ver:"2.7.4+reloaded2-9ubuntu1.1", rls:"UBUNTU16.04 LTS"))) {
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
