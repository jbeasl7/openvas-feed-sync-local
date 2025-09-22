# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703562");
  script_cve_id("CVE-2015-0857", "CVE-2015-0858");
  script_tag(name:"creation_date", value:"2016-04-30 22:00:00 +0000 (Sat, 30 Apr 2016)");
  script_version("2024-02-02T05:06:05+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:05 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-05-06 18:16:56 +0000 (Fri, 06 May 2016)");

  script_name("Debian: Security Advisory (DSA-3562-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8");

  script_xref(name:"Advisory-ID", value:"DSA-3562-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2016/DSA-3562-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-3562");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'tardiff' package(s) announced via the DSA-3562-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities were discovered in tardiff, a tarball comparison tool. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2015-0857

Rainer Mueller and Florian Weimer discovered that tardiff is prone to shell command injections via shell meta-characters in filenames in tar files or via shell meta-characters in the tar filename itself.

CVE-2015-0858

Florian Weimer discovered that tardiff uses predictable temporary directories for unpacking tarballs. A malicious user can use this flaw to overwrite files with permissions of the user running the tardiff command line tool.

For the stable distribution (jessie), these problems have been fixed in version 0.1-2+deb8u2.

For the unstable distribution (sid), these problems have been fixed in version 0.1-5 and partially in earlier versions.

We recommend that you upgrade your tardiff packages.");

  script_tag(name:"affected", value:"'tardiff' package(s) on Debian 8.");

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

  if(!isnull(res = isdpkgvuln(pkg:"tardiff", ver:"0.1-2+deb8u2", rls:"DEB8"))) {
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
