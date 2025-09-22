# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2025.7366.2");
  script_cve_id("CVE-2025-25184", "CVE-2025-27111", "CVE-2025-27610");
  script_tag(name:"creation_date", value:"2025-07-24 12:51:36 +0000 (Thu, 24 Jul 2025)");
  script_version("2025-07-25T05:44:05+0000");
  script_tag(name:"last_modification", value:"2025-07-25 05:44:05 +0000 (Fri, 25 Jul 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Ubuntu: Security Advisory (USN-7366-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU25\.04");

  script_xref(name:"Advisory-ID", value:"USN-7366-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-7366-2");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ruby-rack' package(s) announced via the USN-7366-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-7366-1 fixed vulnerabilities in Rack. This update provides the
corresponding updates for Ubuntu 25.04.

Original advisory details:

 Nhat Thai Do discovered that Rack incorrectly handled certain usernames. A
 remote attacker could possibly use this issue to perform CRLF injection.
 (CVE-2025-25184)

 Pham Quang Minh discovered that Rack incorrectly handled certain headers. A
 remote attacker could possibly use this issue to perform log injection.
 (CVE-2025-27111)

 Pham Quang Minh discovered that Rack did not properly handle relative file
 paths. A remote attacker could potentially exploit this to include local
 files that should have been inaccessible. (CVE-2025-27610)");

  script_tag(name:"affected", value:"'ruby-rack' package(s) on Ubuntu 25.04.");

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

if(release == "UBUNTU25.04") {

  if(!isnull(res = isdpkgvuln(pkg:"ruby-rack", ver:"2.2.7-1.1ubuntu0.25.04.2", rls:"UBUNTU25.04"))) {
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
