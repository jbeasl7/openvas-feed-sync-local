# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.842073");
  script_cve_id("CVE-2014-7923", "CVE-2014-7924", "CVE-2014-7925", "CVE-2014-7926", "CVE-2014-7927", "CVE-2014-7928", "CVE-2014-7929", "CVE-2014-7930", "CVE-2014-7931", "CVE-2014-7932", "CVE-2014-7933", "CVE-2014-7934", "CVE-2014-7937", "CVE-2014-7938", "CVE-2014-7940", "CVE-2014-7942", "CVE-2014-7943", "CVE-2014-7946", "CVE-2014-7948", "CVE-2015-1205", "CVE-2015-1346");
  script_tag(name:"creation_date", value:"2015-01-27 04:50:26 +0000 (Tue, 27 Jan 2015)");
  script_version("2024-02-02T05:06:05+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:05 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Ubuntu: Security Advisory (USN-2476-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(14\.04\ LTS|14\.10)");

  script_xref(name:"Advisory-ID", value:"USN-2476-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2476-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'oxide-qt' package(s) announced via the USN-2476-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several memory corruption bugs were discovered in ICU. If a user were
tricked in to opening a specially crafted website, an attacker could
potentially exploit these to cause a denial of service via renderer crash
or execute arbitrary code with the privileges of the sandboxed render
process. (CVE-2014-7923, CVE-2014-7926)

A use-after-free was discovered in the IndexedDB implementation. If a user
were tricked in to opening a specially crafted website, an attacker could
potentially exploit this to cause a denial of service via application
crash or execute arbitrary code with the privileges of the user invoking
the program. (CVE-2014-7924)

A use-after free was discovered in the WebAudio implementation in Blink.
If a user were tricked in to opening a specially crafted website, an
attacker could potentially exploit this to cause a denial of service via
renderer crash or execute arbitrary code with the privileges of the
sandboxed render process. (CVE-2014-7925)

Several memory corruption bugs were discovered in V8. If a user were
tricked in to opening a specially crafted website, an attacker could
potentially exploit these to cause a denial of service via renderer crash
or execute arbitrary code with the privileges of the sandboxed render
process. (CVE-2014-7927, CVE-2014-7928, CVE-2014-7931)

Several use-after free bugs were discovered in the DOM implementation in
Blink. If a user were tricked in to opening a specially crafted website,
an attacker could potentially exploit these to cause a denial of service
via renderer crash or execute arbitrary code with the privileges of the
sandboxed render process. (CVE-2014-7929, CVE-2014-7930, CVE-2014-7932,
CVE-2014-7934)

A use-after free was discovered in FFmpeg. If a user were tricked in to
opening a specially crafted website, an attacker could potentially exploit
this to cause a denial of service via renderer crash or execute arbitrary
code with the privileges of the sandboxed render process. (CVE-2014-7933)

Multiple off-by-one errors were discovered in FFmpeg. If a user were
tricked in to opening a specially crafted website, an attacker could
potentially exploit this to cause a denial of service via renderer crash
or execute arbitrary code with the privileges of the sandboxed render
process. (CVE-2014-7937)

A memory corruption bug was discovered in the fonts implementation. If a
user were tricked in to opening a specially crafted website, an attacker
could potentially exploit this to cause a denial of service via renderer
crash or execute arbitrary code with the privileges of the sandboxed
render process. (CVE-2014-7938)

It was discovered that ICU did not initialize memory for a data structure
correctly. If a user were tricked in to opening a specially crafted
website, an attacker could potentially exploit this to cause a denial of
service via renderer crash or execute arbitrary code with the privileges
of the sandboxed ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'oxide-qt' package(s) on Ubuntu 14.04, Ubuntu 14.10.");

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

  if(!isnull(res = isdpkgvuln(pkg:"liboxideqtcore0", ver:"1.4.2-0ubuntu0.14.04.1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"oxideqt-codecs", ver:"1.4.2-0ubuntu0.14.04.1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"oxideqt-codecs-extra", ver:"1.4.2-0ubuntu0.14.04.1", rls:"UBUNTU14.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"liboxideqtcore0", ver:"1.4.2-0ubuntu0.14.10.1", rls:"UBUNTU14.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"oxideqt-codecs", ver:"1.4.2-0ubuntu0.14.10.1", rls:"UBUNTU14.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"oxideqt-codecs-extra", ver:"1.4.2-0ubuntu0.14.10.1", rls:"UBUNTU14.10"))) {
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
