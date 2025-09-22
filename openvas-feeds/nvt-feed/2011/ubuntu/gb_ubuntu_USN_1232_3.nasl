# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.840775");
  script_cve_id("CVE-2010-4818");
  script_tag(name:"creation_date", value:"2011-10-21 14:31:29 +0000 (Fri, 21 Oct 2011)");
  script_version("2024-02-28T14:37:42+0000");
  script_tag(name:"last_modification", value:"2024-02-28 14:37:42 +0000 (Wed, 28 Feb 2024)");
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-1232-3)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(10\.04\ LTS|10\.10)");

  script_xref(name:"Advisory-ID", value:"USN-1232-3");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1232-3");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'xorg-server' package(s) announced via the USN-1232-3 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-1232-1 fixed vulnerabilities in the X.Org X server. A regression was
found on Ubuntu 10.04 LTS that affected GLX support, and USN-1232-2 was
released to temporarily disable the problematic security fix. This update
includes a revised fix for CVE-2010-4818.

We apologize for the inconvenience.

Original advisory details:

 It was discovered that the X server incorrectly handled certain malformed
 input. An authorized attacker could exploit this to cause the X server to
 crash, leading to a denial or service, or possibly execute arbitrary code
 with root privileges. This issue only affected Ubuntu 10.04 LTS and 10.10.
 (CVE-2010-4818)

 It was discovered that the X server incorrectly handled certain malformed
 input. An authorized attacker could exploit this to cause the X server to
 crash, leading to a denial or service, or possibly read arbitrary data from
 the X server process. This issue only affected Ubuntu 10.04 LTS.
 (CVE-2010-4819)

 Vladz discovered that the X server incorrectly handled lock files. A local
 attacker could use this flaw to determine if a file existed or not.
 (CVE-2011-4028)

 Vladz discovered that the X server incorrectly handled setting lock file
 permissions. A local attacker could use this flaw to gain read permissions
 on arbitrary files and view sensitive information. (CVE-2011-4029)");

  script_tag(name:"affected", value:"'xorg-server' package(s) on Ubuntu 10.04, Ubuntu 10.10.");

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

if(release == "UBUNTU10.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"xserver-xorg-core", ver:"2:1.7.6-2ubuntu7.10", rls:"UBUNTU10.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU10.10") {

  if(!isnull(res = isdpkgvuln(pkg:"xserver-xorg-core", ver:"2:1.9.0-0ubuntu7.6", rls:"UBUNTU10.10"))) {
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
