# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703178");
  script_cve_id("CVE-2015-2063");
  script_tag(name:"creation_date", value:"2015-03-01 23:00:00 +0000 (Sun, 01 Mar 2015)");
  script_version("2024-02-02T05:06:05+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:05 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");

  script_name("Debian: Security Advisory (DSA-3178-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB7");

  script_xref(name:"Advisory-ID", value:"DSA-3178-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2015/DSA-3178-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-3178");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'unace' package(s) announced via the DSA-3178-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Jakub Wilk discovered that unace, an utility to extract, test and view .ace archives, contained an integer overflow leading to a buffer overflow. If a user or automated system were tricked into processing a specially crafted ace archive, an attacker could cause a denial of service (application crash) or, possibly, execute arbitrary code.

For the stable distribution (wheezy), this problem has been fixed in version 1.2b-10+deb7u1.

For the upcoming stable distribution (jessie), this problem has been fixed in version 1.2b-12.

For the unstable distribution (sid), this problem has been fixed in version 1.2b-12.

We recommend that you upgrade your unace packages.");

  script_tag(name:"affected", value:"'unace' package(s) on Debian 7.");

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

  if(!isnull(res = isdpkgvuln(pkg:"unace", ver:"1.2b-10+deb7u1", rls:"DEB7"))) {
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
