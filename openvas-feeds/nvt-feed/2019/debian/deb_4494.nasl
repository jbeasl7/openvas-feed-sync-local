# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704494");
  script_cve_id("CVE-2019-14744");
  script_tag(name:"creation_date", value:"2019-08-10 02:00:10 +0000 (Sat, 10 Aug 2019)");
  script_version("2024-02-02T05:06:06+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:06 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"5.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-08-15 14:00:49 +0000 (Thu, 15 Aug 2019)");

  script_name("Debian: Security Advisory (DSA-4494-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(10|9)");

  script_xref(name:"Advisory-ID", value:"DSA-4494-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2019/DSA-4494-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-4494");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/kconfig");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'kconfig' package(s) announced via the DSA-4494-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Dominik Penner discovered that KConfig, the KDE configuration settings framework, supported a feature to define shell command execution in .desktop files. If a user is provided with a malformed .desktop file (e.g. if it's embedded into a downloaded archive and it gets opened in a file browser) arbitrary commands could get executed. This update removes this feature.

For the oldstable distribution (stretch), this problem has been fixed in version 5.28.0-2+deb9u1.

For the stable distribution (buster), this problem has been fixed in version 5.54.0-1+deb10u1.

We recommend that you upgrade your kconfig packages.

For the detailed security status of kconfig please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'kconfig' package(s) on Debian 9, Debian 10.");

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

if(release == "DEB10") {

  if(!isnull(res = isdpkgvuln(pkg:"libkf5config-bin", ver:"5.54.0-1+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libkf5config-data", ver:"5.54.0-1+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libkf5config-dev", ver:"5.54.0-1+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libkf5config-dev-bin", ver:"5.54.0-1+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libkf5config-doc", ver:"5.54.0-1+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libkf5configcore5", ver:"5.54.0-1+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libkf5configgui5", ver:"5.54.0-1+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "DEB9") {

  if(!isnull(res = isdpkgvuln(pkg:"libkf5config-bin", ver:"5.28.0-2+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libkf5config-bin-dev", ver:"5.28.0-2+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libkf5config-data", ver:"5.28.0-2+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libkf5config-dev", ver:"5.28.0-2+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libkf5configcore5", ver:"5.28.0-2+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libkf5configgui5", ver:"5.28.0-2+deb9u1", rls:"DEB9"))) {
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
