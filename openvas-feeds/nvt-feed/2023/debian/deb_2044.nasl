# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.1.1.2010.2044");
  script_cve_id("CVE-2010-2062");
  script_tag(name:"creation_date", value:"2023-05-01 04:27:16 +0000 (Mon, 01 May 2023)");
  script_version("2024-02-02T05:06:10+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:10 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-2044-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB5");

  script_xref(name:"Advisory-ID", value:"DSA-2044-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2010/DSA-2044-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-2044");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'mplayer' package(s) announced via the DSA-2044-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"tixxDZ (DZCORE labs) discovered a vulnerability in the mplayer movie player. Missing data validation in mplayer's real data transport (RDT) implementation enable an integer underflow and consequently an unbounded buffer operation. A maliciously crafted stream could thus enable an attacker to execute arbitrary code.

No Common Vulnerabilities and Exposures project identifier is available for this issue.

For the stable distribution (lenny), this problem has been fixed in version 1.0~rc2-17+lenny3.2.

We recommend that you upgrade your mplayer packages.");

  script_tag(name:"affected", value:"'mplayer' package(s) on Debian 5.");

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

if(release == "DEB5") {

  if(!isnull(res = isdpkgvuln(pkg:"mplayer", ver:"1.0~rc2-17+lenny3.2", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mplayer-dbg", ver:"1.0~rc2-17+lenny3.2", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mplayer-doc", ver:"1.0~rc2-17+lenny3.2", rls:"DEB5"))) {
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
