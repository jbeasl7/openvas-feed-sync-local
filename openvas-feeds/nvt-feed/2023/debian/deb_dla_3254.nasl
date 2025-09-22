# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.893254");
  script_cve_id("CVE-2022-4515");
  script_tag(name:"creation_date", value:"2023-01-01 02:00:27 +0000 (Sun, 01 Jan 2023)");
  script_version("2024-02-02T05:06:10+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:10 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-01-03 17:22:43 +0000 (Tue, 03 Jan 2023)");

  script_name("Debian: Security Advisory (DLA-3254-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB10");

  script_xref(name:"Advisory-ID", value:"DLA-3254-1");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2022/DLA-3254-1");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'exuberant-ctags' package(s) announced via the DLA-3254-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A flaw was found in the way the exubertant-ctags source code parser handled the '-o' command-line option which specifies the tag filename. A crafted tag filename specified in the command line or in the configuration file could have resulted in arbitrary command execution because the externalSortTags() in sort.c calls the system(3) function in an unsafe way.

CVE-2022-4515

A flaw was found in Exuberant Ctags in the way it handles the '-o' option. This option specifies the tag filename. A crafted tag filename specified in the command line or in the configuration file results in arbitrary command execution because the externalSortTags() in sort.c calls the system(3) function in an unsafe way.

For Debian 10 Buster, this problem has been fixed in version 1:5.9~svn20110310-12+deb10u1.

We recommend that you upgrade your exuberant-ctags packages.

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'exuberant-ctags' package(s) on Debian 10.");

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

  if(!isnull(res = isdpkgvuln(pkg:"exuberant-ctags", ver:"1:5.9~svn20110310-12+deb10u1", rls:"DEB10"))) {
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
