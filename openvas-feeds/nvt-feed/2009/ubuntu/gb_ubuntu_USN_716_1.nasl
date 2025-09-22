# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.63310");
  script_cve_id("CVE-2008-0780", "CVE-2008-0781", "CVE-2008-0782", "CVE-2008-1098", "CVE-2008-1099", "CVE-2009-0260", "CVE-2009-0312");
  script_tag(name:"creation_date", value:"2009-02-02 22:28:24 +0000 (Mon, 02 Feb 2009)");
  script_version("2024-02-02T05:06:04+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:04 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Ubuntu: Security Advisory (USN-716-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(6\.06\ LTS|7\.10|8\.04\ LTS|8\.10)");

  script_xref(name:"Advisory-ID", value:"USN-716-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-716-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'moin' package(s) announced via the USN-716-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Fernando Quintero discovered than MoinMoin did not properly sanitize its
input when processing login requests, resulting in cross-site scripting (XSS)
vulnerabilities. With cross-site scripting vulnerabilities, if a user were
tricked into viewing server output during a crafted server request, a remote
attacker could exploit this to modify the contents, or steal confidential data,
within the same domain. This issue affected Ubuntu 7.10 and 8.04 LTS.
(CVE-2008-0780)

Fernando Quintero discovered that MoinMoin did not properly sanitize its input
when attaching files, resulting in cross-site scripting vulnerabilities. This
issue affected Ubuntu 6.06 LTS, 7.10 and 8.04 LTS. (CVE-2008-0781)

It was discovered that MoinMoin did not properly sanitize its input when
processing user forms. A remote attacker could submit crafted cookie values and
overwrite arbitrary files via directory traversal. This issue affected Ubuntu
6.06 LTS, 7.10 and 8.04 LTS. (CVE-2008-0782)

It was discovered that MoinMoin did not properly sanitize its input when
editing pages, resulting in cross-site scripting vulnerabilities. This issue
only affected Ubuntu 6.06 LTS and 7.10. (CVE-2008-1098)

It was discovered that MoinMoin did not properly enforce access controls,
which could allow a remoter attacker to view private pages. This issue only
affected Ubuntu 6.06 LTS and 7.10. (CVE-2008-1099)

It was discovered that MoinMoin did not properly sanitize its input when
attaching files and using the rename parameter, resulting in cross-site
scripting vulnerabilities. (CVE-2009-0260)

It was discovered that MoinMoin did not properly sanitize its input when
displaying error messages after processing spam, resulting in cross-site
scripting vulnerabilities. (CVE-2009-0312)");

  script_tag(name:"affected", value:"'moin' package(s) on Ubuntu 6.06, Ubuntu 7.10, Ubuntu 8.04, Ubuntu 8.10.");

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

if(release == "UBUNTU6.06 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"python2.4-moinmoin", ver:"1.5.2-1ubuntu2.4", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU7.10") {

  if(!isnull(res = isdpkgvuln(pkg:"python-moinmoin", ver:"1.5.7-3ubuntu2.1", rls:"UBUNTU7.10"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU8.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"python-moinmoin", ver:"1.5.8-5.1ubuntu2.2", rls:"UBUNTU8.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU8.10") {

  if(!isnull(res = isdpkgvuln(pkg:"python-moinmoin", ver:"1.7.1-1ubuntu1.1", rls:"UBUNTU8.10"))) {
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
