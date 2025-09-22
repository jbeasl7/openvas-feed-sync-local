# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.844353");
  script_cve_id("CVE-2016-9840", "CVE-2016-9841", "CVE-2016-9842", "CVE-2016-9843");
  script_tag(name:"creation_date", value:"2020-02-25 04:00:26 +0000 (Tue, 25 Feb 2020)");
  script_version("2024-02-02T05:06:07+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:07 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-06-01 16:47:18 +0000 (Thu, 01 Jun 2017)");

  script_name("Ubuntu: Security Advisory (USN-4292-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(16\.04\ LTS|18\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-4292-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4292-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'rsync' package(s) announced via the USN-4292-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that rsync incorrectly handled pointer arithmetic in zlib.
An attacker could use this issue to cause rsync to crash, resulting in a
denial of service, or possibly execute arbitrary code. (CVE-2016-9840,
CVE-2016-9841)

It was discovered that rsync incorrectly handled vectors involving left shifts
of negative integers in zlib. An attacker could use this issue to cause rsync
to crash, resulting in a denial of service, or possibly execute arbitrary
code. (CVE-2016-9842)

It was discovered that rsync incorrectly handled vectors involving big-endian
CRC calculation in zlib. An attacker could use this issue to cause rsync to
crash, resulting in a denial of service, or possibly execute arbitrary code.
(CVE-2016-9843)");

  script_tag(name:"affected", value:"'rsync' package(s) on Ubuntu 16.04, Ubuntu 18.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"rsync", ver:"3.1.1-3ubuntu1.3", rls:"UBUNTU16.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"rsync", ver:"3.1.2-2.1ubuntu1.1", rls:"UBUNTU18.04 LTS"))) {
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
