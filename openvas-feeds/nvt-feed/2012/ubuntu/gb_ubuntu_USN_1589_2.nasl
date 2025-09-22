# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.841254");
  script_cve_id("CVE-2012-3480");
  script_tag(name:"creation_date", value:"2012-12-18 04:34:54 +0000 (Tue, 18 Dec 2012)");
  script_version("2024-02-28T14:37:42+0000");
  script_tag(name:"last_modification", value:"2024-02-28 14:37:42 +0000 (Wed, 28 Feb 2024)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Ubuntu: Security Advisory (USN-1589-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU8\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-1589-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1589-2");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'glibc' package(s) announced via the USN-1589-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-1589-1 fixed vulnerabilities in the GNU C Library. One of the updates
exposed a regression in the floating point parser. This update fixes the
problem.

We apologize for the inconvenience.

Original advisory details:

 It was discovered that positional arguments to the printf() family
 of functions were not handled properly in the GNU C Library. An
 attacker could possibly use this to cause a stack-based buffer
 overflow, creating a denial of service or possibly execute arbitrary
 code. (CVE-2012-3404, CVE-2012-3405, CVE-2012-3406)

 It was discovered that multiple integer overflows existed in the
 strtod(), strtof() and strtold() functions in the GNU C Library. An
 attacker could possibly use this to trigger a stack-based buffer
 overflow, creating a denial of service or possibly execute arbitrary
 code. (CVE-2012-3480)");

  script_tag(name:"affected", value:"'glibc' package(s) on Ubuntu 8.04.");

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

if(release == "UBUNTU8.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"libc6", ver:"2.7-10ubuntu8.3", rls:"UBUNTU8.04 LTS"))) {
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
