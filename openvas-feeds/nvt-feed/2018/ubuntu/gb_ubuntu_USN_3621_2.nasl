# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.843690");
  script_cve_id("CVE-2018-1000074");
  script_tag(name:"creation_date", value:"2018-10-26 04:07:14 +0000 (Fri, 26 Oct 2018)");
  script_version("2024-02-28T14:37:42+0000");
  script_tag(name:"last_modification", value:"2024-02-28 14:37:42 +0000 (Wed, 28 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-04-05 21:17:10 +0000 (Thu, 05 Apr 2018)");

  script_name("Ubuntu: Security Advisory (USN-3621-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU14\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-3621-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3621-2");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ruby1.9.1, ruby2.0' package(s) announced via the USN-3621-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-3621-1 fixed vulnerabilities in Ruby. The update caused an issue due
to an incomplete patch for CVE-2018-1000074. This update reverts the
problematic patch pending further investigation.

We apologize for the inconvenience.

Original advisory details:

 It was discovered that Ruby incorrectly handled certain inputs. An attacker
 could possibly use this to access sensitive information. (CVE-2018-1000073)

 It was discovered that Ruby incorrectly handled certain files. An attacker
 could possibly use this to execute arbitrary code. (CVE-2018-1000074)

 It was discovered that Ruby incorrectly handled certain files. An attacker
 could possibly use this to cause a denial of service. (CVE-2018-1000075)

 It was discovered that Ruby incorrectly handled certain crypto signatures.
 An attacker could possibly use this to execute arbitrary code. (CVE-2018-1000076)

 It was discovered that Ruby incorrectly handled certain inputs. An attacker
 could possibly use this to execute arbitrary code. (CVE-2018-1000077,
 CVE-2018-1000078, CVE-2018-1000079)");

  script_tag(name:"affected", value:"'ruby1.9.1, ruby2.0' package(s) on Ubuntu 14.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libruby1.9.1", ver:"1.9.3.484-2ubuntu1.10", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libruby2.0", ver:"2.0.0.484-1ubuntu2.8", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ruby1.9.1", ver:"1.9.3.484-2ubuntu1.10", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ruby1.9.3", ver:"1.9.3.484-2ubuntu1.10", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ruby2.0", ver:"2.0.0.484-1ubuntu2.8", rls:"UBUNTU14.04 LTS"))) {
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
