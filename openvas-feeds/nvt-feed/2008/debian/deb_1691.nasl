# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.63060");
  script_cve_id("CVE-2007-3555", "CVE-2008-1502", "CVE-2008-3325", "CVE-2008-3326", "CVE-2008-4796", "CVE-2008-4810", "CVE-2008-4811", "CVE-2008-5432", "CVE-2008-6124");
  script_tag(name:"creation_date", value:"2008-12-29 21:42:24 +0000 (Mon, 29 Dec 2008)");
  script_version("2024-02-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:10 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-1691-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB4");

  script_xref(name:"Advisory-ID", value:"DSA-1691-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2008/DSA-1691-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-1691");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'moodle' package(s) announced via the DSA-1691-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several remote vulnerabilities have been discovered in Moodle, an online course management system. The following issues are addressed in this update, ranging from cross site scripting to remote code execution.

Various cross site scripting issues in the Moodle codebase (CVE-2008-3326, CVE-2008-3325, CVE-2007-3555, CVE-2008-5432, MSA-08-0021, MDL-8849, MDL-12793, MDL-11414, MDL-14806, MDL-10276).

Various cross site request forgery issues in the Moodle codebase (CVE-2008-3325, MSA-08-0023).

Privilege escalation bugs in the Moodle codebase (MSA-08-0001, MDL-7755).

SQL injection issue in the hotpot module (MSA-08-0010).

An embedded copy of Smarty had several vulnerabilities (CVE-2008-4811, CVE-2008-4810). An embedded copy of Snoopy was vulnerable to cross site scripting (CVE-2008-4796). An embedded copy of Kses was vulnerable to cross site scripting (CVE-2008-1502).

For the stable distribution (etch), these problems have been fixed in version 1.6.3-2+etch1.

For the unstable distribution (sid), these problems have been fixed in version 1.8.2.dfsg-2.

We recommend that you upgrade your moodle (1.6.3-2+etch1) package.");

  script_tag(name:"affected", value:"'moodle' package(s) on Debian 4.");

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

if(release == "DEB4") {

  if(!isnull(res = isdpkgvuln(pkg:"moodle", ver:"1.6.3-2+etch1", rls:"DEB4"))) {
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
