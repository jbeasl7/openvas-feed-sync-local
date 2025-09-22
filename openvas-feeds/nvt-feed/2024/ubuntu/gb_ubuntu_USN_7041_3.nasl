# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2024.7041.3");
  script_cve_id("CVE-2024-47175");
  script_tag(name:"creation_date", value:"2024-10-08 04:07:46 +0000 (Tue, 08 Oct 2024)");
  script_version("2024-10-09T05:05:35+0000");
  script_tag(name:"last_modification", value:"2024-10-09 05:05:35 +0000 (Wed, 09 Oct 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Ubuntu: Security Advisory (USN-7041-3)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU16\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-7041-3");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-7041-3");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'cups' package(s) announced via the USN-7041-3 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-7041-1 fixed a vulnerability in CUPS. This update provides
the corresponding update for Ubuntu 16.04 LTS.

Original advisory details:

 Simone Margaritelli discovered that CUPS incorrectly sanitized IPP
 data when creating PPD files. A remote attacker could possibly use this
 issue to manipulate PPD files and execute arbitrary code when a printer is
 used.");

  script_tag(name:"affected", value:"'cups' package(s) on Ubuntu 16.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"cups", ver:"2.1.3-4ubuntu0.11+esm8", rls:"UBUNTU16.04 LTS"))) {
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
