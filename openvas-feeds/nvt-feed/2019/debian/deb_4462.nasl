# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704462");
  script_cve_id("CVE-2019-12749");
  script_tag(name:"creation_date", value:"2019-06-14 02:00:06 +0000 (Fri, 14 Jun 2019)");
  script_version("2024-02-02T05:06:06+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:06 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"3.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-06-12 15:39:01 +0000 (Wed, 12 Jun 2019)");

  script_name("Debian: Security Advisory (DSA-4462-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");

  script_xref(name:"Advisory-ID", value:"DSA-4462-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2019/DSA-4462-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-4462");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/dbus");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'dbus' package(s) announced via the DSA-4462-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Joe Vennix discovered an authentication bypass vulnerability in dbus, an asynchronous inter-process communication system. The implementation of the DBUS_COOKIE_SHA1 authentication mechanism was susceptible to a symbolic link attack. A local attacker could take advantage of this flaw to bypass authentication and connect to a DBusServer with elevated privileges.

The standard system and session dbus-daemons in their default configuration are not affected by this vulnerability.

The vulnerability was addressed by upgrading dbus to a new upstream version 1.10.28 which includes additional fixes.

For the stable distribution (stretch), this problem has been fixed in version 1.10.28-0+deb9u1.

We recommend that you upgrade your dbus packages.

For the detailed security status of dbus please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'dbus' package(s) on Debian 9.");

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

if(release == "DEB9") {

  if(!isnull(res = isdpkgvuln(pkg:"dbus", ver:"1.10.28-0+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dbus-1-dbg", ver:"1.10.28-0+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dbus-1-doc", ver:"1.10.28-0+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dbus-tests", ver:"1.10.28-0+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dbus-udeb", ver:"1.10.28-0+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dbus-user-session", ver:"1.10.28-0+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dbus-x11", ver:"1.10.28-0+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libdbus-1-3", ver:"1.10.28-0+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libdbus-1-3-udeb", ver:"1.10.28-0+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libdbus-1-dev", ver:"1.10.28-0+deb9u1", rls:"DEB9"))) {
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
