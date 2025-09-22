# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2024.7042.3");
  script_cve_id("CVE-2024-47176");
  script_tag(name:"creation_date", value:"2024-10-22 04:08:09 +0000 (Tue, 22 Oct 2024)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Ubuntu: Security Advisory (USN-7042-3)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU24\.10");

  script_xref(name:"Advisory-ID", value:"USN-7042-3");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-7042-3");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'cups-browsed' package(s) announced via the USN-7042-3 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-7042-2 released an improved fix for cups-browsed. This update provides
the corresponding update for Ubuntu 24.10.

Original advisory details:

 Simone Margaritelli discovered that cups-browsed could be used to create
 arbitrary printers from outside the local network. In combination with
 issues in other printing components, a remote attacker could possibly use
 this issue to connect to a system, created manipulated PPD files, and
 execute arbitrary code when a printer is used. This update disables
 support for the legacy CUPS printer discovery protocol.");

  script_tag(name:"affected", value:"'cups-browsed' package(s) on Ubuntu 24.10.");

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

if(release == "UBUNTU24.10") {

  if(!isnull(res = isdpkgvuln(pkg:"cups-browsed", ver:"2.0.1-0ubuntu2.1", rls:"UBUNTU24.10"))) {
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
