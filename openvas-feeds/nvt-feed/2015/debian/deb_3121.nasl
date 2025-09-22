# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703121");
  script_cve_id("CVE-2014-8116", "CVE-2014-8117", "CVE-2014-9620", "CVE-2014-9652");
  script_tag(name:"creation_date", value:"2015-01-07 23:00:00 +0000 (Wed, 07 Jan 2015)");
  script_version("2024-02-02T05:06:05+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:05 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_name("Debian: Security Advisory (DSA-3121-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB7");

  script_xref(name:"Advisory-ID", value:"DSA-3121-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2015/DSA-3121-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-3121");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'file' package(s) announced via the DSA-3121-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple security issues have been found in file, a tool/library to determine a file type. Processing a malformed file could result in denial of service. Most of the changes are related to parsing ELF files.

As part of the fixes, several limits on aspects of the detection were added or tightened, sometimes resulting in messages like recursion limit exceeded or too many program header sections.

To mitigate such shortcomings, these limits are controllable by a new - -P, --parameter option in the file program.

For the stable distribution (wheezy), these problems have been fixed in version 5.11-2+deb7u7.

For the upcoming stable distribution (jessie), these problems will be fixed soon.

For the unstable distribution (sid), these problems have been fixed in version 1:5.21+15-1.

We recommend that you upgrade your file packages.");

  script_tag(name:"affected", value:"'file' package(s) on Debian 7.");

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

  if(!isnull(res = isdpkgvuln(pkg:"file", ver:"5.11-2+deb7u7", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmagic-dev", ver:"5.11-2+deb7u7", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmagic1", ver:"5.11-2+deb7u7", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python-magic", ver:"5.11-2+deb7u7", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python-magic-dbg", ver:"5.11-2+deb7u7", rls:"DEB7"))) {
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
