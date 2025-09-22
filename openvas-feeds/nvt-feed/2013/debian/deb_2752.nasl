# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.702752");
  script_cve_id("CVE-2013-5724");
  script_tag(name:"creation_date", value:"2013-09-06 22:00:00 +0000 (Fri, 06 Sep 2013)");
  script_version("2024-02-02T05:06:04+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:04 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:P/A:N");

  script_name("Debian: Security Advisory (DSA-2752-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(6|7)");

  script_xref(name:"Advisory-ID", value:"DSA-2752-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2013/DSA-2752-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-2752");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'phpbb3' package(s) announced via the DSA-2752-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Andreas Beckmann discovered that phpBB, a web forum, as installed in Debian, sets incorrect permissions for cached files, allowing a malicious local user to overwrite them.

For the oldstable distribution (squeeze), this problem has been fixed in version 3.0.7-PL1-4+squeeze1.

For the stable distribution (wheezy), this problem has been fixed in version 3.0.10-4+deb7u1.

For the unstable distribution (sid), this problem has been fixed in version 3.0.11-4.

We recommend that you upgrade your phpbb3 packages.");

  script_tag(name:"affected", value:"'phpbb3' package(s) on Debian 6, Debian 7.");

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

if(release == "DEB6") {

  if(!isnull(res = isdpkgvuln(pkg:"phpbb3", ver:"3.0.7-PL1-4+squeeze1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"phpbb3-l10n", ver:"3.0.7-PL1-4+squeeze1", rls:"DEB6"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "DEB7") {

  if(!isnull(res = isdpkgvuln(pkg:"phpbb3", ver:"3.0.10-4+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"phpbb3-l10n", ver:"3.0.10-4+deb7u1", rls:"DEB7"))) {
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
