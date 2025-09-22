# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.893035");
  script_cve_id("CVE-2014-10402");
  script_tag(name:"creation_date", value:"2022-06-01 13:28:14 +0000 (Wed, 01 Jun 2022)");
  script_version("2024-02-02T05:06:08+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:08 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"3.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:L");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-10-02 16:13:09 +0000 (Fri, 02 Oct 2020)");

  script_name("Debian: Security Advisory (DLA-3035-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");

  script_xref(name:"Advisory-ID", value:"DLA-3035-1");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2022/DLA-3035-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/libdbi-perl");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'libdbi-perl' package(s) announced via the DLA-3035-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that CVE-2014-10401 was fixed incompletely in the Perl5 Database Interface (DBI). An attacker could trigger information disclosure through a different vector.

CVE-2014-10401

DBD::File drivers can open files from folders other than those specifically passed via the f_dir attribute.

CVE-2014-10402

DBD::File drivers can open files from folders other than those specifically passed via the f_dir attribute in the data source name (DSN). NOTE: this issue exists because of an incomplete fix for CVE-2014-10401.

For Debian 9 stretch, this problem has been fixed in version 1.636-1+deb9u2.

We recommend that you upgrade your libdbi-perl packages.

For the detailed security status of libdbi-perl please refer to its security tracker page at: [link moved to references]

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'libdbi-perl' package(s) on Debian 9.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libdbi-perl", ver:"1.636-1+deb9u2", rls:"DEB9"))) {
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
