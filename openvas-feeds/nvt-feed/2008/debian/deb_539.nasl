# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.53229");
  script_cve_id("CVE-2004-0689");
  script_tag(name:"creation_date", value:"2008-01-17 21:45:44 +0000 (Thu, 17 Jan 2008)");
  script_version("2024-02-02T05:06:04+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:04 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-01-26 17:06:25 +0000 (Fri, 26 Jan 2024)");

  script_name("Debian: Security Advisory (DSA-539)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB3\.0");

  script_xref(name:"Advisory-ID", value:"DSA-539");
  script_xref(name:"URL", value:"https://www.debian.org/security/2004/DSA-539");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-539");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'kdelibs' package(s) announced via the DSA-539 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE security team was alerted that in some cases the integrity of symlinks used by KDE are not ensured and that these symlinks can be pointing to stale locations. This can be abused by a local attacker to create or truncate arbitrary files or to prevent KDE applications from functioning correctly.

For the stable distribution (woody) this problem has been fixed in version 2.2.2-13.woody.12.

For the unstable distribution (sid) this problem has been fixed in version 3.3.0-1.

We recommend that you upgrade your kde packages.");

  script_tag(name:"affected", value:"'kdelibs' package(s) on Debian 3.0.");

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

if(release == "DEB3.0") {

  if(!isnull(res = isdpkgvuln(pkg:"kdelibs-dev", ver:"4:2.2.2-13.woody.12", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kdelibs3", ver:"4:2.2.2-13.woody.12", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kdelibs3-bin", ver:"4:2.2.2-13.woody.12", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kdelibs3-cups", ver:"4:2.2.2-13.woody.12", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kdelibs3-doc", ver:"4:2.2.2-13.woody.12", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libarts", ver:"4:2.2.2-13.woody.12", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libarts-alsa", ver:"4:2.2.2-13.woody.12", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libarts-dev", ver:"4:2.2.2-13.woody.12", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libkmid", ver:"4:2.2.2-13.woody.12", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libkmid-alsa", ver:"4:2.2.2-13.woody.12", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libkmid-dev", ver:"4:2.2.2-13.woody.12", rls:"DEB3.0"))) {
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
