# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703572");
  script_cve_id("CVE-2016-1236");
  script_tag(name:"creation_date", value:"2016-05-08 22:00:00 +0000 (Sun, 08 May 2016)");
  script_version("2024-02-02T05:06:05+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:05 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-05-13 14:45:41 +0000 (Fri, 13 May 2016)");

  script_name("Debian: Security Advisory (DSA-3572-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8");

  script_xref(name:"Advisory-ID", value:"DSA-3572-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2016/DSA-3572-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-3572");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'websvn' package(s) announced via the DSA-3572-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Nitin Venkatesh discovered that websvn, a web viewer for Subversion repositories, is susceptible to cross-site scripting attacks via specially crafted file and directory names in repositories.

For the stable distribution (jessie), this problem has been fixed in version 2.3.3-1.2+deb8u2.

We recommend that you upgrade your websvn packages.");

  script_tag(name:"affected", value:"'websvn' package(s) on Debian 8.");

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

if(release == "DEB8") {

  if(!isnull(res = isdpkgvuln(pkg:"websvn", ver:"2.3.3-1.2+deb8u2", rls:"DEB8"))) {
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
