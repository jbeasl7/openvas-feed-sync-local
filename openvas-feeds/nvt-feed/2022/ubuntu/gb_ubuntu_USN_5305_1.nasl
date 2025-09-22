# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.845261");
  script_cve_id("CVE-2021-46659", "CVE-2021-46661", "CVE-2021-46663", "CVE-2021-46664", "CVE-2021-46665", "CVE-2021-46668", "CVE-2022-24048", "CVE-2022-24050", "CVE-2022-24051", "CVE-2022-24052");
  script_tag(name:"creation_date", value:"2022-03-01 02:00:29 +0000 (Tue, 01 Mar 2022)");
  script_version("2024-02-02T05:06:10+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:10 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-02-28 14:46:31 +0000 (Mon, 28 Feb 2022)");

  script_name("Ubuntu: Security Advisory (USN-5305-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(20\.04\ LTS|21\.10)");

  script_xref(name:"Advisory-ID", value:"USN-5305-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5305-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'mariadb-10.3, mariadb-10.5' package(s) announced via the USN-5305-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several security issues were discovered in MariaDB and this update includes
new upstream MariaDB versions to fix these issues.

MariaDB has been updated to 10.3.34 in Ubuntu 20.04 LTS and to 10.5.15 in
Ubuntu 21.10.

In addition to security fixes, the updated packages contain bug fixes,
new features, and possibly incompatible changes.");

  script_tag(name:"affected", value:"'mariadb-10.3, mariadb-10.5' package(s) on Ubuntu 20.04, Ubuntu 21.10.");

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

  if(!isnull(res = isdpkgvuln(pkg:"mariadb-server", ver:"1:10.3.34-0ubuntu0.20.04.1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU21.10") {

  if(!isnull(res = isdpkgvuln(pkg:"mariadb-server", ver:"1:10.5.15-0ubuntu0.21.10.1", rls:"UBUNTU21.10"))) {
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
