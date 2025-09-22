# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703035");
  script_cve_id("CVE-2014-7169", "CVE-2014-7186", "CVE-2014-7187");
  script_tag(name:"creation_date", value:"2014-10-01 11:30:22 +0000 (Wed, 01 Oct 2014)");
  script_version("2024-08-08T05:05:41+0000");
  script_tag(name:"last_modification", value:"2024-08-08 05:05:41 +0000 (Thu, 08 Aug 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-07-24 16:47:58 +0000 (Wed, 24 Jul 2024)");

  script_name("Debian: Security Advisory (DSA-3035-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB7");

  script_xref(name:"Advisory-ID", value:"DSA-3035-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2014/DSA-3035-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-3035");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'bash' package(s) announced via the DSA-3035-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Tavis Ormandy discovered that the patch applied to fix CVE-2014-6271 released in DSA-3032-1 for bash, the GNU Bourne-Again Shell, was incomplete and could still allow some characters to be injected into another environment (CVE-2014-7169). With this update prefix and suffix for environment variable names which contain shell functions are added as hardening measure.

Additionally two out-of-bounds array accesses in the bash parser are fixed which were revealed in Red Hat's internal analysis for these issues and also independently reported by Todd Sabin.

For the stable distribution (wheezy), these problems have been fixed in version 4.2+dfsg-0.1+deb7u3.

We recommend that you upgrade your bash packages.");

  script_tag(name:"affected", value:"'bash' package(s) on Debian 7.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");

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

  if(!isnull(res = isdpkgvuln(pkg:"bash", ver:"4.2+dfsg-0.1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"bash-builtins", ver:"4.2+dfsg-0.1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"bash-doc", ver:"4.2+dfsg-0.1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"bash-static", ver:"4.2+dfsg-0.1+deb7u3", rls:"DEB7"))) {
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
