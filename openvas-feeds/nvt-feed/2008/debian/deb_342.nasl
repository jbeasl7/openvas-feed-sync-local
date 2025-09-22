# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.53631");
  script_cve_id("CVE-2003-0538");
  script_tag(name:"creation_date", value:"2008-01-17 21:36:24 +0000 (Thu, 17 Jan 2008)");
  script_version("2024-02-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:10 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-342)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB3\.0");

  script_xref(name:"Advisory-ID", value:"DSA-342");
  script_xref(name:"URL", value:"https://www.debian.org/security/2003/DSA-342");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-342");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'mozart' package(s) announced via the DSA-342 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"mozart, a development platform based on the Oz language, includes MIME configuration data which specifies that Oz applications should be passed to the Oz interpreter for execution. This means that file managers, web browsers, and other programs which honor the mailcap file could automatically execute Oz programs downloaded from untrusted sources. Thus, a malicious Oz program could execute arbitrary code under the uid of a user running a MIME-aware client program if the user selected a file (for example, choosing a link in a web browser).

For the stable distribution (woody) this problem has been fixed in version 1.2.3.20011204-3woody1.

For the unstable distribution (sid) this problem has been fixed in version 1.2.5.20030212-2.

We recommend that you update your mozart package.");

  script_tag(name:"affected", value:"'mozart' package(s) on Debian 3.0.");

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

if(release == "DEB3.0") {

  if(!isnull(res = isdpkgvuln(pkg:"mozart", ver:"1.2.3.20011204-3woody1", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mozart-contrib", ver:"1.2.3.20011204-3woody1", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mozart-doc-html", ver:"1.2.3.20011204-3woody1", rls:"DEB3.0"))) {
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
