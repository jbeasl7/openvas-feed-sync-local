# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.53786");
  script_cve_id("CVE-2001-0361");
  script_version("2023-07-19T05:05:15+0000");
  script_tag(name:"last_modification", value:"2023-07-19 05:05:15 +0000 (Wed, 19 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-01-17 14:24:38 +0100 (Thu, 17 Jan 2008)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:P/A:N");
  script_name("Debian Security Advisory DSA 023-1 (inn2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB2\.2");
  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=DSA%20023-1");
  script_tag(name:"insight", value:"1. People at WireX have found several potential insecure uses of
temporary files in programs provided by INN2.  Some of them only
lead to a vulnerability to symlink attacks if the temporary
directory was set to /tmp or /var/tmp, which is the case in many
installations, at least in Debian packages.  An attacker could
overwrite any file owned by the news system administrator,
i.e. owned by news.news.

2. Michal Zalewski found an exploitable buffer overflow with regard
to cancel messages and their verification.  This bug did only show
up if 'verifycancels' was enabled in inn.conf which is not the
default and has been disrecommended by upstream.

3. Andi Kleen found a bug in INN2 that makes innd crash for two byte
headers.  There is a chance this can only be exploited with uucp.

We recommend you upgrade your inn2 packages immediately.");
  script_tag(name:"summary", value:"The remote host is missing an update to inn2
announced via advisory DSA 023-1.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution", value:"Please install the updated package(s).");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"inn2-dev", ver:"2.2.2.2000.01.31-4.1", rls:"DEB2.2")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"inn2-inews", ver:"2.2.2.2000.01.31-4.1", rls:"DEB2.2")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"inn2", ver:"2.2.2.2000.01.31-4.1", rls:"DEB2.2")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"task-news-server", ver:"2.2.2.2000.01.31-4.1", rls:"DEB2.2")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}
