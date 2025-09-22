# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703502");
  script_cve_id("CVE-2014-6276");
  script_tag(name:"creation_date", value:"2016-03-08 07:07:54 +0000 (Tue, 08 Mar 2016)");
  script_version("2024-02-02T05:06:05+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:05 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-04-15 14:45:54 +0000 (Fri, 15 Apr 2016)");

  script_name("Debian: Security Advisory (DSA-3502-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(7|8)");

  script_xref(name:"Advisory-ID", value:"DSA-3502-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2016/DSA-3502-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-3502");
  script_xref(name:"URL", value:"http://www.roundup-tracker.org/docs/upgrading.html#user-data-visibility");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'roundup' package(s) announced via the DSA-3502-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Ralf Schlatterbeck discovered an information leak in roundup, a web-based issue tracking system. An authenticated attacker could use it to see sensitive details about other users, including their hashed password.

After applying the update, which will fix the shipped templates, the site administrator should ensure the instanced versions (in /var/lib/roundup usually) are also updated, either by patching them manually or by recreating them.

More info can be found in the upstream documentation at [link moved to references]

For the oldstable distribution (wheezy), this problem has been fixed in version 1.4.20-1.1+deb7u1.

For the stable distribution (jessie), this problem has been fixed in version 1.4.20-1.1+deb8u1.

For the testing (stretch) and unstable (sid) distribution, this problem has not yet been fixed.

We recommend that you upgrade your roundup packages.");

  script_tag(name:"affected", value:"'roundup' package(s) on Debian 7, Debian 8.");

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

if(release == "DEB7") {

  if(!isnull(res = isdpkgvuln(pkg:"roundup", ver:"1.4.20-1.1+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "DEB8") {

  if(!isnull(res = isdpkgvuln(pkg:"roundup", ver:"1.4.20-1.1+deb8u1", rls:"DEB8"))) {
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
