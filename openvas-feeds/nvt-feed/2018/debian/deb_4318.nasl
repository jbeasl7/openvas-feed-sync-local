# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704318");
  script_cve_id("CVE-2017-5934");
  script_tag(name:"creation_date", value:"2018-10-14 22:00:00 +0000 (Sun, 14 Oct 2018)");
  script_version("2024-02-02T05:06:06+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:06 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-11-29 13:00:19 +0000 (Thu, 29 Nov 2018)");

  script_name("Debian: Security Advisory (DSA-4318-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");

  script_xref(name:"Advisory-ID", value:"DSA-4318-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2018/DSA-4318-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-4318");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/moin");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'moin' package(s) announced via the DSA-4318-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Nitin Venkatesh discovered a cross-site scripting vulnerability in moin, a Python clone of WikiWiki. A remote attacker can conduct cross-site scripting attacks via the GUI editor's link dialogue. This only affects installations which have set up fckeditor (not enabled by default).

For the stable distribution (stretch), this problem has been fixed in version 1.9.9-1+deb9u1.

We recommend that you upgrade your moin packages.

For the detailed security status of moin please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'moin' package(s) on Debian 9.");

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

  if(!isnull(res = isdpkgvuln(pkg:"python-moinmoin", ver:"1.9.9-1+deb9u1", rls:"DEB9"))) {
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
