# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703213");
  script_cve_id("CVE-2015-0556", "CVE-2015-0557", "CVE-2015-2782");
  script_tag(name:"creation_date", value:"2015-04-05 22:00:00 +0000 (Sun, 05 Apr 2015)");
  script_version("2024-02-02T05:06:05+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:05 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-3213-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB7");

  script_xref(name:"Advisory-ID", value:"DSA-3213-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2015/DSA-3213-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-3213");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'arj' package(s) announced via the DSA-3213-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple vulnerabilities have been discovered in arj, an open source version of the arj archiver. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2015-0556

Jakub Wilk discovered that arj follows symlinks created during unpacking of an arj archive. A remote attacker could use this flaw to perform a directory traversal attack if a user or automated system were tricked into processing a specially crafted arj archive.

CVE-2015-0557

Jakub Wilk discovered that arj does not sufficiently protect from directory traversal while unpacking an arj archive containing file paths with multiple leading slashes. A remote attacker could use this flaw to write to arbitrary files if a user or automated system were tricked into processing a specially crafted arj archive.

CVE-2015-2782

Jakub Wilk and Guillem Jover discovered a buffer overflow vulnerability in arj. A remote attacker could use this flaw to cause an application crash or, possibly, execute arbitrary code with the privileges of the user running arj.

For the stable distribution (wheezy), these problems have been fixed in version 3.10.22-10+deb7u1.

For the upcoming stable distribution (jessie), these problems have been fixed in version 3.10.22-13.

For the unstable distribution (sid), these problems have been fixed in version 3.10.22-13.

We recommend that you upgrade your arj packages.");

  script_tag(name:"affected", value:"'arj' package(s) on Debian 7.");

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

  if(!isnull(res = isdpkgvuln(pkg:"arj", ver:"3.10.22-10+deb7u1", rls:"DEB7"))) {
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
