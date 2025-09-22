# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.67270");
  script_cve_id("CVE-2010-0436");
  script_tag(name:"creation_date", value:"2010-04-21 01:31:17 +0000 (Wed, 21 Apr 2010)");
  script_version("2024-02-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:10 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-2037-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB5");

  script_xref(name:"Advisory-ID", value:"DSA-2037-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2010/DSA-2037-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-2037");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'kdebase' package(s) announced via the DSA-2037-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Sebastian Krahmer discovered that a race condition in the KDE Desktop Environment's KDM display manager, allow a local user to elevate privileges to root.

For the stable distribution (lenny), this problem has been fixed in version 4:3.5.9.dfsg.1-6+lenny1.

For the unstable distribution (sid), this problem will be fixed soon.

We recommend that you upgrade your kdm package.");

  script_tag(name:"affected", value:"'kdebase' package(s) on Debian 5.");

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

if(release == "DEB5") {

  if(!isnull(res = isdpkgvuln(pkg:"kappfinder", ver:"4:3.5.9.dfsg.1-6+lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kate", ver:"4:3.5.9.dfsg.1-6+lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kcontrol", ver:"4:3.5.9.dfsg.1-6+lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kdebase", ver:"4:3.5.9.dfsg.1-6+lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kdebase-bin", ver:"4:3.5.9.dfsg.1-6+lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kdebase-bin-kde3", ver:"4:3.5.9.dfsg.1-6+lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kdebase-data", ver:"4:3.5.9.dfsg.1-6+lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kdebase-dbg", ver:"4:3.5.9.dfsg.1-6+lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kdebase-dev", ver:"4:3.5.9.dfsg.1-6+lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kdebase-doc", ver:"4:3.5.9.dfsg.1-6+lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kdebase-doc-html", ver:"4:3.5.9.dfsg.1-6+lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kdebase-kio-plugins", ver:"4:3.5.9.dfsg.1-6+lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kdeeject", ver:"4:3.5.9.dfsg.1-6+lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kdepasswd", ver:"4:3.5.9.dfsg.1-6+lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kdeprint", ver:"4:3.5.9.dfsg.1-6+lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kdesktop", ver:"4:3.5.9.dfsg.1-6+lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kdm", ver:"4:3.5.9.dfsg.1-6+lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kfind", ver:"4:3.5.9.dfsg.1-6+lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"khelpcenter", ver:"4:4.0.0.really.3.5.9.dfsg.1-6+lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kicker", ver:"4:3.5.9.dfsg.1-6+lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"klipper", ver:"4:3.5.9.dfsg.1-6+lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kmenuedit", ver:"4:3.5.9.dfsg.1-6+lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"konqueror", ver:"4:3.5.9.dfsg.1-6+lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"konqueror-nsplugins", ver:"4:3.5.9.dfsg.1-6+lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"konsole", ver:"4:3.5.9.dfsg.1-6+lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kpager", ver:"4:3.5.9.dfsg.1-6+lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kpersonalizer", ver:"4:3.5.9.dfsg.1-6+lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ksmserver", ver:"4:3.5.9.dfsg.1-6+lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ksplash", ver:"4:3.5.9.dfsg.1-6+lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ksysguard", ver:"4:3.5.9.dfsg.1-6+lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ksysguardd", ver:"4:3.5.9.dfsg.1-6+lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ktip", ver:"4:3.5.9.dfsg.1-6+lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kwin", ver:"4:3.5.9.dfsg.1-6+lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libkonq4", ver:"4:3.5.9.dfsg.1-6+lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libkonq4-dev", ver:"4:3.5.9.dfsg.1-6+lenny1", rls:"DEB5"))) {
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
