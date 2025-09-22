# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.63397");
  script_cve_id("CVE-2009-0352", "CVE-2009-0353", "CVE-2009-0354", "CVE-2009-0355", "CVE-2009-0357", "CVE-2009-0358");
  script_tag(name:"creation_date", value:"2009-02-13 19:43:17 +0000 (Fri, 13 Feb 2009)");
  script_version("2024-02-02T05:06:04+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:04 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-717-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(8\.04\ LTS|8\.10)");

  script_xref(name:"Advisory-ID", value:"USN-717-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-717-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'firefox-3.0, xulrunner-1.9' package(s) announced via the USN-717-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several flaws were discovered in the browser engine. These problems could allow
an attacker to crash the browser and possibly execute arbitrary code with user
privileges. (CVE-2009-0352, CVE-2009-0353)

A flaw was discovered in the JavaScript engine. An attacker could bypass the
same-origin policy in Firefox by utilizing a chrome XBL method and execute
arbitrary JavaScript within the context of another website. (CVE-2009-0354)

A flaw was discovered in the browser engine when restoring closed tabs. If a
user were tricked into restoring a tab to a malicious website with form input
controls, an attacker could steal local files on the user's system.
(CVE-2009-0355)

Wladimir Palant discovered that Firefox did not restrict access to cookies in
HTTP response headers. If a user were tricked into opening a malicious web
page, a remote attacker could view sensitive information. (CVE-2009-0357)

Paul Nel discovered that Firefox did not honor certain Cache-Control HTTP
directives. A local attacker could exploit this to view private data in
improperly cached pages of another user. (CVE-2009-0358)");

  script_tag(name:"affected", value:"'firefox-3.0, xulrunner-1.9' package(s) on Ubuntu 8.04, Ubuntu 8.10.");

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

if(release == "UBUNTU8.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"firefox-3.0", ver:"3.0.6+nobinonly-0ubuntu0.8.04.1", rls:"UBUNTU8.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xulrunner-1.9", ver:"1.9.0.6+nobinonly-0ubuntu0.8.04.1", rls:"UBUNTU8.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"abrowser", ver:"3.0.6+nobinonly-0ubuntu0.8.10.1", rls:"UBUNTU8.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-3.0", ver:"3.0.6+nobinonly-0ubuntu0.8.10.1", rls:"UBUNTU8.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xulrunner-1.9", ver:"1.9.0.6+nobinonly-0ubuntu0.8.10.1", rls:"UBUNTU8.10"))) {
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
