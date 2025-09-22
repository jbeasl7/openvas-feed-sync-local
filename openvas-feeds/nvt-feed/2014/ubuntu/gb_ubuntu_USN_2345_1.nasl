# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.842005");
  script_cve_id("CVE-2014-3178", "CVE-2014-3179", "CVE-2014-3188", "CVE-2014-3190", "CVE-2014-3191", "CVE-2014-3192", "CVE-2014-3194", "CVE-2014-3195", "CVE-2014-3197", "CVE-2014-3199", "CVE-2014-3200", "CVE-2014-7967");
  script_tag(name:"creation_date", value:"2014-10-15 04:09:08 +0000 (Wed, 15 Oct 2014)");
  script_version("2024-02-02T05:06:05+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:05 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-2345-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU14\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-2345-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2345-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'oxide-qt' package(s) announced via the USN-2345-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple use-after-free issues were discovered in Blink. If a user were
tricked in to opening a specially crafted website, an attacker could
potentially exploit these to cause a denial of service via renderer crash,
or execute arbitrary code with the privileges of the sandboxed render
process. (CVE-2014-3178, CVE-2014-3190, CVE-2014-3191, CVE-2014-3192)

Multiple security issues were discovered in Chromium. If a user were
tricked in to opening a specially crafted website, an attacker could
potentially exploit these to read uninitialized memory, cause a denial of
service via application crash or execute arbitrary code with the
privileges of the user invoking the program. (CVE-2014-3179,
CVE-2014-3200)

It was discovered that Chromium did not properly handle the interaction of
IPC and V8. If a user were tricked in to opening a specially crafted
website, an attacker could potentially exploit this to execute arbitrary
code with the privileges of the user invoking the program. (CVE-2014-3188)

A use-after-free was discovered in the web workers implementation in
Chromium. If a user were tricked in to opening a specially crafted website,
an attacker could potentially exploit this to cause a denial of service
via application crash or execute arbitrary code with the privileges of the
user invoking the program. (CVE-2014-3194)

It was discovered that V8 did not correctly handle Javascript heap
allocations in some circumstances. If a user were tricked in to opening a
specially crafted website, an attacker could potentially exploit this to
steal sensitive information. (CVE-2014-3195)

It was discovered that Blink did not properly provide substitute data for
pages blocked by the XSS auditor. If a user were tricked in to opening a
specially crafter website, an attacker could potentially exploit this to
steal sensitive information. (CVE-2014-3197)

It was discovered that the wrap function for Event's in the V8 bindings
in Blink produced an erroneous result in some circumstances. If a user
were tricked in to opening a specially crafted website, an attacker could
potentially exploit this to cause a denial of service by stopping a worker
process that was handling an Event object. (CVE-2014-3199)

Multiple security issues were discovered in V8. If a user were tricked in
to opening a specially crafted website, an attacker could potentially
exploit these to read uninitialized memory, cause a denial of service via
renderer crash or execute arbitrary code with the privileges of the
sandboxed render process. (CVE-2014-7967)");

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

  if(!isnull(res = isdpkgvuln(pkg:"liboxideqtcore0", ver:"1.2.5-0ubuntu0.14.04.1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"oxideqt-codecs", ver:"1.2.5-0ubuntu0.14.04.1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"oxideqt-codecs-extra", ver:"1.2.5-0ubuntu0.14.04.1", rls:"UBUNTU14.04 LTS"))) {
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
