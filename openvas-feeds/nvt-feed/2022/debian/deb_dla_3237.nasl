# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.893237");
  script_cve_id("CVE-2021-37701", "CVE-2021-37712");
  script_tag(name:"creation_date", value:"2022-12-13 02:00:10 +0000 (Tue, 13 Dec 2022)");
  script_version("2024-02-02T05:06:08+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:08 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"4.4");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-09-09 18:02:56 +0000 (Thu, 09 Sep 2021)");

  script_name("Debian: Security Advisory (DLA-3237-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB10");

  script_xref(name:"Advisory-ID", value:"DLA-3237-1");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2022/DLA-3237-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/node-tar");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'node-tar' package(s) announced via the DLA-3237-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Cache poisoning vulnerabilities were found in node-tar, a Node.js module used to read and write portable tar archives, which may result in arbitrary file creation or overwrite.

CVE-2021-37701

It was discovered that node-tar performed insufficient symlink protection, thereby making directory cache vulnerable to poisoning using symbolic links.

Upon extracting an archive containing a directory `foo/bar` followed with a symbolic link `foobar` to an arbitrary location, node-tar would extract arbitrary files into the symlink target, thus allowing arbitrary file creation and overwrite.

Moreover, on case-insensitive filesystems, a similar issue occurred with a directory `FOO` followed with a symbolic link `foo`.

CVE-2021-37712

Similar to CVE-2021-37701, a specially crafted tar archive containing two directories and a symlink with names containing unicode values that normalized to the same value, would bypass node-tar's symlink checks on directories, thus allowing arbitrary file creation and overwrite.

For Debian 10 buster, these problems have been fixed in version 4.4.6+ds1-3+deb10u2.

We recommend that you upgrade your node-tar packages.

For the detailed security status of node-tar please refer to its security tracker page at: [link moved to references]

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'node-tar' package(s) on Debian 10.");

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

  if(!isnull(res = isdpkgvuln(pkg:"node-tar", ver:"4.4.6+ds1-3+deb10u2", rls:"DEB10"))) {
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
