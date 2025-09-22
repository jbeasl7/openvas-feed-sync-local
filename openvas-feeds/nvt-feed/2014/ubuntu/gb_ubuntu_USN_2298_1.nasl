# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.841913");
  script_cve_id("CVE-2014-1730", "CVE-2014-1731", "CVE-2014-1735", "CVE-2014-1740", "CVE-2014-1741", "CVE-2014-1742", "CVE-2014-1743", "CVE-2014-1744", "CVE-2014-1746", "CVE-2014-1748", "CVE-2014-3152", "CVE-2014-3154", "CVE-2014-3155", "CVE-2014-3157", "CVE-2014-3160", "CVE-2014-3162", "CVE-2014-3803");
  script_tag(name:"creation_date", value:"2014-07-28 11:09:33 +0000 (Mon, 28 Jul 2014)");
  script_version("2024-02-02T05:06:05+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:05 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");

  script_name("Ubuntu: Security Advisory (USN-2298-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU14\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-2298-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2298-1");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/1337301");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'oxide-qt' package(s) announced via the USN-2298-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A type confusion bug was discovered in V8. If a user were tricked in to
opening a specially crafted website, an attacker could potentially exploit
this to cause a denial of service via renderer crash, or execute arbitrary
code with the privileges of the sandboxed render process. (CVE-2014-1730)

A type confusion bug was discovered in Blink. If a user were tricked in to
opening a specially crafted website, an attacker could potentially exploit
this to cause a denial of service via renderer crash, or execute arbitrary
code with the privileges of the sandboxed render process. (CVE-2014-1731)

Multiple security issues including memory safety bugs were discovered in
Chromium. If a user were tricked in to opening a specially crafted website,
an attacker could potentially exploit these to cause a denial of service via
application crash or execute arbitrary code with the privileges of the
user invoking the program. (CVE-2014-1735, CVE-2014-3162)

Multiple use-after-free issues were discovered in the WebSockets
implementation. If a user were tricked in to opening a specially crafted
website, an attacker could potentially exploit these to cause a denial of
service via application crash or execute arbitrary code with the
privileges of the user invoking the program. (CVE-2014-1740)

Multiple integer overflows were discovered in CharacterData
implementation. If a user were tricked in to opening a specially crafted
website, an attacker could potentially exploit these to cause a denial of
service via renderer crash or execute arbitrary code with the privileges
of the sandboxed render process. (CVE-2014-1741)

Multiple use-after-free issues were discovered in Blink. If a user were
tricked in to opening a specially crafted website, an attacker could
potentially exploit these to cause a denial of service via renderer crash
or execute arbitrary code with the privileges of the sandboxed render
process. (CVE-2014-1742, CVE-2014-1743)

An integer overflow bug was discovered in Chromium. If a user were
tricked in to opening a specially crafted website, an attacker could
potentially exploit this to cause a denial of service via application
crash or execute arbitrary code with the privileges of the user invoking
the program. (CVE-2014-1744)

An out-of-bounds read was discovered in Chromium. If a user were tricked
in to opening a specially crafter website, an attacker could potentially
exploit this to cause a denial of service via application crash.
(CVE-2014-1746)

It was discovered that Blink allowed scrollbar painting to extend in to
the parent frame in some circumstances. An attacker could potentially
exploit this to conduct clickjacking attacks via UI redress.
(CVE-2014-1748)

An integer underflow was discovered in Blink. If a user were tricked in to
opening a specially crafter website, an attacker could potentially exploit
this to cause a denial of service via renderer crash or execute ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'oxide-qt' package(s) on Ubuntu 14.04.");

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

if(release == "UBUNTU14.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"liboxideqtcore0", ver:"1.0.4-0ubuntu0.14.04.1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"oxideqt-codecs", ver:"1.0.4-0ubuntu0.14.04.1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"oxideqt-codecs-extra", ver:"1.0.4-0ubuntu0.14.04.1", rls:"UBUNTU14.04 LTS"))) {
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
