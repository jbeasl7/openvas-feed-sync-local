# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704243");
  script_cve_id("CVE-2017-15400", "CVE-2018-4180", "CVE-2018-4181", "CVE-2018-6553");
  script_tag(name:"creation_date", value:"2018-07-10 22:00:00 +0000 (Tue, 10 Jul 2018)");
  script_version("2024-02-02T05:06:06+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:06 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-10-10 14:34:44 +0000 (Wed, 10 Oct 2018)");

  script_name("Debian: Security Advisory (DSA-4243-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");

  script_xref(name:"Advisory-ID", value:"DSA-4243-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2018/DSA-4243-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-4243");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/cups");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'cups' package(s) announced via the DSA-4243-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities were discovered in CUPS, the Common UNIX Printing System. These issues have been identified with the following CVE ids:

CVE-2017-15400

Rory McNamara discovered that an attacker is able to execute arbitrary commands (with the privilege of the CUPS daemon) by setting a malicious IPP server with a crafted PPD file.

CVE-2018-4180

Dan Bastone of Gotham Digital Science discovered that a local attacker with access to cupsctl could escalate privileges by setting an environment variable.

CVE-2018-4181

Eric Rafaloff and John Dunlap of Gotham Digital Science discovered that a local attacker can perform limited reads of arbitrary files as root by manipulating cupsd.conf.

CVE-2018-6553

Dan Bastone of Gotham Digital Science discovered that an attacker can bypass the AppArmor cupsd sandbox by invoking the dnssd backend using an alternate name that has been hard linked to dnssd.

For the stable distribution (stretch), these problems have been fixed in version 2.2.1-8+deb9u2.

We recommend that you upgrade your cups packages.

For the detailed security status of cups please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'cups' package(s) on Debian 9.");

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

  if(!isnull(res = isdpkgvuln(pkg:"cups", ver:"2.2.1-8+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cups-bsd", ver:"2.2.1-8+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cups-client", ver:"2.2.1-8+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cups-common", ver:"2.2.1-8+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cups-core-drivers", ver:"2.2.1-8+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cups-daemon", ver:"2.2.1-8+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cups-ipp-utils", ver:"2.2.1-8+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cups-ppdc", ver:"2.2.1-8+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cups-server-common", ver:"2.2.1-8+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libcups2", ver:"2.2.1-8+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libcups2-dev", ver:"2.2.1-8+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libcupscgi1", ver:"2.2.1-8+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libcupsimage2", ver:"2.2.1-8+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libcupsimage2-dev", ver:"2.2.1-8+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libcupsmime1", ver:"2.2.1-8+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libcupsppdc1", ver:"2.2.1-8+deb9u2", rls:"DEB9"))) {
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
