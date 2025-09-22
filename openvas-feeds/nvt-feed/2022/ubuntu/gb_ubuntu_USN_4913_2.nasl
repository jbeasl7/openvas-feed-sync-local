# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.845225");
  script_cve_id("CVE-2021-23358");
  script_tag(name:"creation_date", value:"2022-01-28 08:01:55 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-02-02T05:06:10+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:10 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-04-12 16:35:06 +0000 (Mon, 12 Apr 2021)");

  script_name("Ubuntu: Security Advisory (USN-4913-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU21\.04");

  script_xref(name:"Advisory-ID", value:"USN-4913-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4913-2");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'underscore' package(s) announced via the USN-4913-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-4913-1 fixed vulnerabilities in Underscore. This update provides
the corresponding updates for Ubuntu 21.04.

Original advisory details:

 It was discovered that Underscore incorrectly handled certain inputs.
 An attacker could possibly use this issue to inject arbitrary code.");

  script_tag(name:"affected", value:"'underscore' package(s) on Ubuntu 21.04.");

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

if(release == "UBUNTU21.04") {

  if(!isnull(res = isdpkgvuln(pkg:"libjs-underscore", ver:"1.9.1~dfsg-1ubuntu0.21.04.1", rls:"UBUNTU21.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"node-underscore", ver:"1.9.1~dfsg-1ubuntu0.21.04.1", rls:"UBUNTU21.04"))) {
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
