# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.842181");
  script_cve_id("CVE-2015-1235", "CVE-2015-1236", "CVE-2015-1237", "CVE-2015-1238", "CVE-2015-1240", "CVE-2015-1241", "CVE-2015-1242", "CVE-2015-1244", "CVE-2015-1246", "CVE-2015-1249", "CVE-2015-1321", "CVE-2015-3333");
  script_tag(name:"creation_date", value:"2015-04-28 03:17:12 +0000 (Tue, 28 Apr 2015)");
  script_version("2024-02-02T05:06:05+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:05 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Ubuntu: Security Advisory (USN-2570-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(14\.04\ LTS|14\.10|15\.04)");

  script_xref(name:"Advisory-ID", value:"USN-2570-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2570-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'oxide-qt' package(s) announced via the USN-2570-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"An issue was discovered in the HTML parser in Blink. If a user were
tricked in to opening a specially crafted website, an attacker could
potentially exploit this to bypass same-origin restrictions.
(CVE-2015-1235)

An issue was discovered in the Web Audio API implementation in Blink. If
a user were tricked in to opening a specially crafted website, an attacker
could potentially exploit this to bypass same-origin restrictions.
(CVE-2015-1236)

A use-after-free was discovered in Chromium. If a user were tricked in to
opening a specially crafted website, an attacker could potentially exploit
this to cause a denial of service via renderer crash, or execute arbitrary
code with the privileges of the sandboxed render process. (CVE-2015-1237)

An out-of-bounds write was discovered in Skia. If a user were tricked in
to opening a specially crafted website, an attacker could potentially
exploit this to cause a denial of service via application crash or execute
arbitrary code with the privileges of the user invoking the program.
(CVE-2015-1238)

An out-of-bounds read was discovered in the WebGL implementation. If a
user were tricked in to opening a specially crafted website, an attacker
could potentially exploit this to cause a denial of service via renderer
crash. (CVE-2015-1240)

An issue was discovered with the interaction of page navigation and touch
event handling. If a user were tricked in to opening a specially crafted
website, an attacker could potentially exploit this to conduct
'tap jacking' attacks. (CVE-2015-1241)

A type confusion bug was discovered in V8. If a user were tricked in to
opening a specially crafted website, an attacker could potentially exploit
this to cause a denial of service via renderer crash, or execute arbitrary
code with the privileges of the sandboxed render process. (CVE-2015-1242)

It was discovered that websocket connections were not upgraded whenever a
HSTS policy is active. A remote attacker could potentially exploit this
to conduct a machine-in-the-middle (MITM) attack. (CVE-2015-1244)

An out-of-bounds read was discovered in Blink. If a user were tricked in
to opening a specially crafted website, an attacker could potentially
exploit this to cause a denial of service via renderer crash.
(CVE-2015-1246)

Multiple security issues were discovered in Chromium. If a user were
tricked in to opening a specially crafted website, an attacker could
potentially exploit these to read uninitialized memory, cause a denial
of service via application crash or execute arbitrary code with the
privileges of the user invoking the program. (CVE-2015-1249)

A use-after-free was discovered in the file picker implementation. If a
user were tricked in to opening a specially crafted website, an attacker
could potentially exploit this to cause a denial of service via
application crash or execute arbitrary code with the privileges of the
user invoking the program. ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'oxide-qt' package(s) on Ubuntu 14.04, Ubuntu 14.10, Ubuntu 15.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"liboxideqtcore0", ver:"1.6.5-0ubuntu0.14.04.1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"oxideqt-codecs", ver:"1.6.5-0ubuntu0.14.04.1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"oxideqt-codecs-extra", ver:"1.6.5-0ubuntu0.14.04.1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU14.10") {

  if(!isnull(res = isdpkgvuln(pkg:"liboxideqtcore0", ver:"1.6.5-0ubuntu0.14.10.1", rls:"UBUNTU14.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"oxideqt-codecs", ver:"1.6.5-0ubuntu0.14.10.1", rls:"UBUNTU14.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"oxideqt-codecs-extra", ver:"1.6.5-0ubuntu0.14.10.1", rls:"UBUNTU14.10"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU15.04") {

  if(!isnull(res = isdpkgvuln(pkg:"liboxideqtcore0", ver:"1.6.5-0ubuntu0.15.04.1", rls:"UBUNTU15.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"oxideqt-codecs", ver:"1.6.5-0ubuntu0.15.04.1", rls:"UBUNTU15.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"oxideqt-codecs-extra", ver:"1.6.5-0ubuntu0.15.04.1", rls:"UBUNTU15.04"))) {
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
