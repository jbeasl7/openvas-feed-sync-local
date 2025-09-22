# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.840431");
  script_cve_id("CVE-2010-1000", "CVE-2010-1511");
  script_tag(name:"creation_date", value:"2010-05-17 14:00:10 +0000 (Mon, 17 May 2010)");
  script_version("2024-02-02T05:06:04+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:04 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:P");

  script_name("Ubuntu: Security Advisory (USN-938-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(10\.04\ LTS|9\.04|9\.10)");

  script_xref(name:"Advisory-ID", value:"USN-938-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-938-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kdenetwork' package(s) announced via the USN-938-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that KGet did not properly perform input validation when
processing metalink files. If a user were tricked into opening a crafted
metalink file, a remote attacker could overwrite files via directory
traversal, which could eventually lead to arbitrary code execution.
(CVE-2010-1000)

It was discovered that KGet would not always wait for user confirmation
when downloading metalink files. If a user selected a file to download
but did not confirm or cancel the download, KGet would proceed with the
download, overwriting any file with the same name. This issue only
affected Ubuntu 10.04 LTS. (CVE-2010-1511)");

  script_tag(name:"affected", value:"'kdenetwork' package(s) on Ubuntu 9.04, Ubuntu 9.10, Ubuntu 10.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"kget", ver:"4:4.4.2-0ubuntu4.1", rls:"UBUNTU10.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU9.04") {

  if(!isnull(res = isdpkgvuln(pkg:"kget", ver:"4:4.2.2-0ubuntu2.3", rls:"UBUNTU9.04"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU9.10") {

  if(!isnull(res = isdpkgvuln(pkg:"kget", ver:"4:4.3.2-0ubuntu4.1", rls:"UBUNTU9.10"))) {
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
