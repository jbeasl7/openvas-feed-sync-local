# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.840665");
  script_tag(name:"creation_date", value:"2011-06-03 07:20:26 +0000 (Fri, 03 Jun 2011)");
  script_version("2023-06-21T05:06:20+0000");
  script_tag(name:"last_modification", value:"2023-06-21 05:06:20 +0000 (Wed, 21 Jun 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Ubuntu: Security Advisory (USN-1138-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(10\.04\ LTS|8\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-1138-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1138-2");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/616517");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'modemmanager, network-manager' package(s) announced via the USN-1138-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-1138-1 fixed a vulnerability in DBus-GLib. NetworkManager and
ModemManager required rebuilding against the updated DBus-GLib to
incorporate the changes.

Original advisory details:

 It was discovered that DBus-GLib did not properly verify the access flag of
 exported GObject properties under certain circumstances. A local attacker
 could exploit this to bypass intended access restrictions or possibly
 cause a denial of service.");

  script_tag(name:"affected", value:"'modemmanager, network-manager' package(s) on Ubuntu 8.04, Ubuntu 10.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libnm-glib2", ver:"0.8-0ubuntu3.2", rls:"UBUNTU10.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"modemmanager", ver:"0.3-0ubuntu2.2", rls:"UBUNTU10.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libnm-glib0", ver:"0.6.6-0ubuntu5.8.04.3", rls:"UBUNTU8.04 LTS"))) {
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
