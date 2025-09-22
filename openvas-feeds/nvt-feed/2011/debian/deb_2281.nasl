# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.69990");
  script_cve_id("CVE-2011-2489", "CVE-2011-2490");
  script_tag(name:"creation_date", value:"2011-08-03 02:36:20 +0000 (Wed, 03 Aug 2011)");
  script_version("2024-02-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:10 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-2281-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(5|6)");

  script_xref(name:"Advisory-ID", value:"DSA-2281-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2011/DSA-2281-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-2281");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'opie' package(s) announced via the DSA-2281-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Sebastian Krahmer discovered that opie, a system that makes it simple to use One-Time passwords in applications, is prone to a privilege escalation (CVE-2011-2490) and an off-by-one error, which can lead to the execution of arbitrary code (CVE-2011-2489). Adam Zabrocki and Maksymilian Arciemowicz also discovered another off-by-one error (CVE-2010-1938), which only affects the lenny version as the fix was already included in squeeze.

For the oldstable distribution (lenny), these problems have been fixed in version 2.32-10.2+lenny2.

For the stable distribution (squeeze), these problems have been fixed in version 2.32.dfsg.1-0.2+squeeze1

The testing distribution (wheezy) and the unstable distribution (sid) do not contain opie.

We recommend that you upgrade your opie packages.");

  script_tag(name:"affected", value:"'opie' package(s) on Debian 5, Debian 6.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libopie-dev", ver:"2.32-10.2+lenny2", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"opie-client", ver:"2.32-10.2+lenny2", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"opie-server", ver:"2.32-10.2+lenny2", rls:"DEB5"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "DEB6") {

  if(!isnull(res = isdpkgvuln(pkg:"libopie-dev", ver:"2.32.dfsg.1-0.2+squeeze1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"opie-client", ver:"2.32.dfsg.1-0.2+squeeze1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"opie-server", ver:"2.32.dfsg.1-0.2+squeeze1", rls:"DEB6"))) {
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
