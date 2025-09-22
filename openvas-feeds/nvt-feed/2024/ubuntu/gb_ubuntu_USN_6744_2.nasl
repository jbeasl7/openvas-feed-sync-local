# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2024.6744.2");
  script_cve_id("CVE-2024-28219");
  script_tag(name:"creation_date", value:"2024-04-24 04:09:36 +0000 (Wed, 24 Apr 2024)");
  script_version("2024-04-25T05:05:14+0000");
  script_tag(name:"last_modification", value:"2024-04-25 05:05:14 +0000 (Thu, 25 Apr 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Ubuntu: Security Advisory (USN-6744-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU20\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-6744-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6744-2");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'pillow-python2' package(s) announced via the USN-6744-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-6744-1 fixed a vulnerability in Pillow (Python 3). This update
provides the corresponding updates for Pillow (Python 2) in
Ubuntu 20.04 LTS.

Original advisory details:

 Hugo van Kemenade discovered that Pillow was not properly performing
 bounds checks when processing an ICC file, which could lead to a buffer
 overflow. If a user or automated system were tricked into processing a
 specially crafted ICC file, an attacker could possibly use this issue
 to cause a denial of service or execute arbitrary code.");

  script_tag(name:"affected", value:"'pillow-python2' package(s) on Ubuntu 20.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"python-pil", ver:"6.2.1-3ubuntu0.1~esm2", rls:"UBUNTU20.04 LTS"))) {
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
