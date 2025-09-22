# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.53605");
  script_cve_id("CVE-2003-0358", "CVE-2003-0359");
  script_tag(name:"creation_date", value:"2008-01-17 21:36:24 +0000 (Thu, 17 Jan 2008)");
  script_version("2024-02-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:10 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-316)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB3\.0");

  script_xref(name:"Advisory-ID", value:"DSA-316");
  script_xref(name:"URL", value:"https://www.debian.org/security/2003/DSA-316");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-316");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'nethack, slashem' package(s) announced via the DSA-316 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The nethack and slashem packages are vulnerable to a buffer overflow exploited via a long '-s' command line option. This vulnerability could be used by an attacker to gain gid 'games' on a system where nethack is installed.

Additionally, some setgid binaries in the nethack package have incorrect permissions, which could allow a user who gains gid 'games' to replace these binaries, potentially causing other users to execute malicious code when they run nethack.

Note that slashem does not contain the file permission problem CAN-2003-0359.

For the stable distribution (woody) these problems have been fixed in version 3.4.0-3.0woody3.

For the old stable distribution (potato) these problems have been fixed in version 3.3.0-7potato1.

For the unstable distribution (sid) these problems are fixed in version 3.4.1-1.

We recommend that you update your nethack package.

For the stable distribution (woody) these problems have been fixed in version 0.0.6E4F8-4.0woody3.

For the old stable distribution (potato) these problems have been fixed in version 0.0.5E7-3potato1.

For the unstable distribution (sid) these problems are fixed in version 0.0.6E4F8-6.

We recommend that you update your slashem package.");

  script_tag(name:"affected", value:"'nethack, slashem' package(s) on Debian 3.0.");

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

  if(!isnull(res = isdpkgvuln(pkg:"nethack", ver:"3.4.0-3.0woody3", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nethack-common", ver:"3.4.0-3.0woody3", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nethack-gnome", ver:"3.4.0-3.0woody3", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nethack-qt", ver:"3.4.0-3.0woody3", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nethack-x11", ver:"3.4.0-3.0woody3", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"slashem", ver:"0.0.6E4F8-4.0woody3", rls:"DEB3.0"))) {
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
