# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.840769");
  script_cve_id("CVE-2011-1678", "CVE-2011-2724", "CVE-2011-3585");
  script_tag(name:"creation_date", value:"2011-10-10 14:05:48 +0000 (Mon, 10 Oct 2011)");
  script_version("2024-02-02T05:06:04+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:04 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"3.3");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-01-10 17:53:17 +0000 (Fri, 10 Jan 2020)");

  script_name("Ubuntu: Security Advisory (USN-1226-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(10\.04\ LTS|8\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-1226-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1226-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'samba' package(s) announced via the USN-1226-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Dan Rosenberg discovered that Samba incorrectly handled changes to the mtab
file. A local attacker could use this issue to corrupt the mtab file,
possibly leading to a denial of service. (CVE-2011-1678)

Jan Lieskovsky discovered that Samba incorrectly filtered certain strings
being added to the mtab file. A local attacker could use this issue to
corrupt the mtab file, possibly leading to a denial of service. This issue
only affected Ubuntu 10.04 LTS. (CVE-2011-2724)

Dan Rosenberg discovered that Samba incorrectly handled the mtab lock file.
A local attacker could use this issue to create a stale lock file, possibly
leading to a denial of service. (CVE-2011-3585)");

  script_tag(name:"affected", value:"'samba' package(s) on Ubuntu 8.04, Ubuntu 10.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"smbfs", ver:"2:3.4.7~dfsg-1ubuntu3.8", rls:"UBUNTU10.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU8.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"smbfs", ver:"3.0.28a-1ubuntu4.16", rls:"UBUNTU8.04 LTS"))) {
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
