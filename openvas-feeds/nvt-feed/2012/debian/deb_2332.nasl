# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.70548");
  script_cve_id("CVE-2011-4136", "CVE-2011-4137", "CVE-2011-4138", "CVE-2011-4139", "CVE-2011-4140");
  script_tag(name:"creation_date", value:"2012-02-11 07:27:22 +0000 (Sat, 11 Feb 2012)");
  script_version("2024-02-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:10 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-2332-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(5|6)");

  script_xref(name:"Advisory-ID", value:"DSA-2332-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2011/DSA-2332-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-2332");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'python-django' package(s) announced via the DSA-2332-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Paul McMillan, Mozilla and the Django core team discovered several vulnerabilities in Django, a Python web framework:

CVE-2011-4136

When using memory-based sessions and caching, Django sessions are stored directly in the root namespace of the cache. When user data is stored in the same cache, a remote user may take over a session.

CVE-2011-4137, CVE-2011-4138 Django's field type URLfield by default checks supplied URL's by issuing a request to it, which doesn't time out. A Denial of Service is possible by supplying specially prepared URL's that keep the connection open indefinitely or fill the Django's server memory.

CVE-2011-4139

Django used X-Forwarded-Host headers to construct full URL's. This header may not contain trusted input and could be used to poison the cache.

CVE-2011-4140

The CSRF protection mechanism in Django does not properly handle web-server configurations supporting arbitrary HTTP Host headers, which allows remote attackers to trigger unauthenticated forged requests.

For the oldstable distribution (lenny), this problem has been fixed in version 1.0.2-1+lenny3.

For the stable distribution (squeeze), this problem has been fixed in version 1.2.3-3+squeeze2.

For the testing (wheezy) and unstable distribution (sid), this problem has been fixed in version 1.3.1-1.

We recommend that you upgrade your python-django packages.");

  script_tag(name:"affected", value:"'python-django' package(s) on Debian 5, Debian 6.");

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

  if(!isnull(res = isdpkgvuln(pkg:"python-django", ver:"1.0.2-1+lenny3", rls:"DEB5"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"python-django", ver:"1.2.3-3+squeeze2", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python-django-doc", ver:"1.2.3-3+squeeze2", rls:"DEB6"))) {
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
