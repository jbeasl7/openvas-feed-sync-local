# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.58614");
  script_cve_id("CVE-2007-4569");
  script_tag(name:"creation_date", value:"2008-01-17 22:19:52 +0000 (Thu, 17 Jan 2008)");
  script_version("2024-02-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:10 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-1376-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB4");

  script_xref(name:"Advisory-ID", value:"DSA-1376-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2007/DSA-1376-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-1376");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'kdebase' package(s) announced via the DSA-1376-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"iKees Huijgen discovered that under certain circumstances KDM, an X session manager for KDE, could be tricked into allowing user logins without a password.

For the old stable distribution (sarge), this problem was not present.

For the stable distribution (etch), this problem has been fixed in version 4:3.5.5a.dfsg.1-6etch1.

We recommend that you upgrade your kdebase package.");

  script_tag(name:"affected", value:"'kdebase' package(s) on Debian 4.");

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

  if(!isnull(res = isdpkgvuln(pkg:"kappfinder", ver:"4:3.5.5a.dfsg.1-6etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kate", ver:"4:3.5.5a.dfsg.1-6etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kcontrol", ver:"4:3.5.5a.dfsg.1-6etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kdebase", ver:"4:3.5.5a.dfsg.1-6etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kdebase-bin", ver:"4:3.5.5a.dfsg.1-6etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kdebase-data", ver:"4:3.5.5a.dfsg.1-6etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kdebase-dbg", ver:"4:3.5.5a.dfsg.1-6etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kdebase-dev", ver:"4:3.5.5a.dfsg.1-6etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kdebase-doc", ver:"4:3.5.5a.dfsg.1-6etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kdebase-doc-html", ver:"4:3.5.5a.dfsg.1-6etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kdebase-kio-plugins", ver:"4:3.5.5a.dfsg.1-6etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kdepasswd", ver:"4:3.5.5a.dfsg.1-6etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kdeprint", ver:"4:3.5.5a.dfsg.1-6etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kdesktop", ver:"4:3.5.5a.dfsg.1-6etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kdm", ver:"4:3.5.5a.dfsg.1-6etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kfind", ver:"4:3.5.5a.dfsg.1-6etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"khelpcenter", ver:"4:3.5.5a.dfsg.1-6etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kicker", ver:"4:3.5.5a.dfsg.1-6etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"klipper", ver:"4:3.5.5a.dfsg.1-6etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kmenuedit", ver:"4:3.5.5a.dfsg.1-6etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"konqueror", ver:"4:3.5.5a.dfsg.1-6etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"konqueror-nsplugins", ver:"4:3.5.5a.dfsg.1-6etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"konsole", ver:"4:3.5.5a.dfsg.1-6etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kpager", ver:"4:3.5.5a.dfsg.1-6etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kpersonalizer", ver:"4:3.5.5a.dfsg.1-6etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ksmserver", ver:"4:3.5.5a.dfsg.1-6etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ksplash", ver:"4:3.5.5a.dfsg.1-6etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ksysguard", ver:"4:3.5.5a.dfsg.1-6etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ksysguardd", ver:"4:3.5.5a.dfsg.1-6etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ktip", ver:"4:3.5.5a.dfsg.1-6etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kwin", ver:"4:3.5.5a.dfsg.1-6etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libkonq4", ver:"4:3.5.5a.dfsg.1-6etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libkonq4-dev", ver:"4:3.5.5a.dfsg.1-6etch1", rls:"DEB4"))) {
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
