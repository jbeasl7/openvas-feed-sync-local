# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.66593");
  script_cve_id("CVE-2009-0365");
  script_tag(name:"creation_date", value:"2009-12-30 20:58:43 +0000 (Wed, 30 Dec 2009)");
  script_version("2024-02-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:10 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:N/A:N");

  script_name("Debian: Security Advisory (DSA-1955-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(4|5)");

  script_xref(name:"Advisory-ID", value:"DSA-1955-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2009/DSA-1955-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-1955");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'network-manager, network-manager-applet' package(s) announced via the DSA-1955-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that network-manager-applet, a network management framework, lacks some dbus restriction rules, which allows local users to obtain sensitive information.

If you have locally modified the /etc/dbus-1/system.d/nm-applet.conf file, then please make sure that you merge the changes from this fix when asked during upgrade.

For the oldstable distribution (etch), this problem has been fixed in version 0.6.4-6+etch1 of network-manager.

For the stable distribution (lenny), this problem has been fixed in version 0.6.6-4+lenny1 of network-manager-applet.

For the testing distribution (squeeze) and the unstable distribution (sid), this problem has been fixed in version 0.7.0.99-1 of network-manager-applet.

We recommend that you upgrade your network-manager and network-manager-applet packages accordingly.");

  script_tag(name:"affected", value:"'network-manager, network-manager-applet' package(s) on Debian 4, Debian 5.");

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

if(release == "DEB4") {

  if(!isnull(res = isdpkgvuln(pkg:"libnm-glib-dev", ver:"0.6.4-6+etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libnm-glib0", ver:"0.6.4-6+etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libnm-util-dev", ver:"0.6.4-6+etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libnm-util0", ver:"0.6.4-6+etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"network-manager", ver:"0.6.4-6+etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"network-manager-dev", ver:"0.6.4-6+etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"network-manager-gnome", ver:"0.6.4-6+etch1", rls:"DEB4"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "DEB5") {

  if(!isnull(res = isdpkgvuln(pkg:"network-manager-gnome", ver:"0.6.6-4+lenny1", rls:"DEB5"))) {
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
