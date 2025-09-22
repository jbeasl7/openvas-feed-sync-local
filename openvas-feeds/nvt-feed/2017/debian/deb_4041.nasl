# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704041");
  script_cve_id("CVE-2017-16844");
  script_tag(name:"creation_date", value:"2017-11-18 23:00:00 +0000 (Sat, 18 Nov 2017)");
  script_version("2024-02-02T05:06:06+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:06 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-12-02 12:59:45 +0000 (Sat, 02 Dec 2017)");

  script_name("Debian: Security Advisory (DSA-4041-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(8|9)");

  script_xref(name:"Advisory-ID", value:"DSA-4041-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2017/DSA-4041-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-4041");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/procmail");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'procmail' package(s) announced via the DSA-4041-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Jakub Wilk reported a heap-based buffer overflow vulnerability in procmail's formail utility when processing specially-crafted email headers. A remote attacker could use this flaw to cause formail to crash, resulting in a denial of service or data loss.

For the oldstable distribution (jessie), this problem has been fixed in version 3.22-24+deb8u1.

For the stable distribution (stretch), this problem has been fixed in version 3.22-25+deb9u1.

We recommend that you upgrade your procmail packages.

For the detailed security status of procmail please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'procmail' package(s) on Debian 8, Debian 9.");

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

  if(!isnull(res = isdpkgvuln(pkg:"procmail", ver:"3.22-24+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "DEB9") {

  if(!isnull(res = isdpkgvuln(pkg:"procmail", ver:"3.22-25+deb9u1", rls:"DEB9"))) {
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
