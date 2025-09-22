# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.841314");
  script_cve_id("CVE-2013-1050");
  script_tag(name:"creation_date", value:"2013-02-15 05:55:14 +0000 (Fri, 15 Feb 2013)");
  script_version("2024-02-02T05:06:04+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:04 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-1716-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU12\.10");

  script_xref(name:"Advisory-ID", value:"USN-1716-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1716-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'gnome-screensaver' package(s) announced via the USN-1716-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that gnome-screensaver did not start automatically after
logging in. This may result in the screen not being automatically locked
after the inactivity timeout is reached, permitting an attacker with
physical access to gain access to an unlocked session.");

  script_tag(name:"affected", value:"'gnome-screensaver' package(s) on Ubuntu 12.10.");

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

if(release == "UBUNTU12.10") {

  if(!isnull(res = isdpkgvuln(pkg:"gnome-screensaver", ver:"3.6.0-0ubuntu2.1", rls:"UBUNTU12.10"))) {
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
