# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.840454");
  script_cve_id("CVE-2008-5913", "CVE-2010-1121", "CVE-2010-1125", "CVE-2010-1196", "CVE-2010-1197", "CVE-2010-1198", "CVE-2010-1199", "CVE-2010-1200", "CVE-2010-1201", "CVE-2010-1202", "CVE-2010-1203");
  script_tag(name:"creation_date", value:"2010-07-02 12:26:21 +0000 (Fri, 02 Jul 2010)");
  script_version("2024-02-02T05:06:04+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:04 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-930-3)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU8\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-930-3");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-930-3");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/600022");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'apturl, firefox-3.0' package(s) announced via the USN-930-3 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-930-1 fixed vulnerabilities in Firefox. Due to a software packaging
problem, the Firefox 3.6 update could not be installed when the firefox-2
package was also installed. This update fixes the problem and updates
apturl for the change.

Original advisory details:

 If was discovered that Firefox could be made to access freed memory. If a
 user were tricked into viewing a malicious site, a remote attacker could
 cause a denial of service or possibly execute arbitrary code with the
 privileges of the user invoking the program. This issue only affected
 Ubuntu 8.04 LTS. (CVE-2010-1121)

 Several flaws were discovered in the browser engine of Firefox. If a
 user were tricked into viewing a malicious site, a remote attacker could
 cause a denial of service or possibly execute arbitrary code with the
 privileges of the user invoking the program. (CVE-2010-1200, CVE-2010-1201,
 CVE-2010-1202, CVE-2010-1203)

 A flaw was discovered in the way plugin instances interacted. An attacker
 could potentially exploit this and use one plugin to access freed memory from a
 second plugin to execute arbitrary code with the privileges of the user
 invoking the program. (CVE-2010-1198)

 An integer overflow was discovered in Firefox. If a user were tricked into
 viewing a malicious site, an attacker could overflow a buffer and cause a
 denial of service or possibly execute arbitrary code with the privileges of
 the user invoking the program. (CVE-2010-1196)

 Martin Barbella discovered an integer overflow in an XSLT node sorting
 routine. An attacker could exploit this to overflow a buffer and cause a
 denial of service or possibly execute arbitrary code with the privileges of
 the user invoking the program. (CVE-2010-1199)

 Michal Zalewski discovered that the focus behavior of Firefox could be
 subverted. If a user were tricked into viewing a malicious site, a remote
 attacker could use this to capture keystrokes. (CVE-2010-1125)

 Ilja van Sprundel discovered that the 'Content-Disposition: attachment'
 HTTP header was ignored when 'Content-Type: multipart' was also present.
 Under certain circumstances, this could potentially lead to cross-site
 scripting attacks. (CVE-2010-1197)

 Amit Klein discovered that Firefox did not seed its random number generator
 often enough. An attacker could exploit this to identify and track users
 across different web sites. (CVE-2008-5913)");

  script_tag(name:"affected", value:"'apturl, firefox-3.0' package(s) on Ubuntu 8.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"apturl", ver:"0.2.2ubuntu1.2", rls:"UBUNTU8.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-3.0", ver:"3.6.6+nobinonly-0ubuntu0.8.04.2", rls:"UBUNTU8.04 LTS"))) {
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
