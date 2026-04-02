# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2026.8077.1");
  script_cve_id("CVE-2018-7753", "CVE-2020-6802", "CVE-2020-6816", "CVE-2020-6817", "CVE-2021-23980");
  script_tag(name:"creation_date", value:"2026-03-09 04:37:02 +0000 (Mon, 09 Mar 2026)");
  script_version("2026-03-10T10:15:11+0000");
  script_tag(name:"last_modification", value:"2026-03-10 10:15:11 +0000 (Tue, 10 Mar 2026)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-03-29 13:50:45 +0000 (Thu, 29 Mar 2018)");

  script_name("Ubuntu: Security Advisory (USN-8077-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(16\.04\ LTS|18\.04\ LTS|20\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-8077-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-8077-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python-bleach' package(s) announced via the USN-8077-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that Bleach did not properly sanitize URI attributes
containing character entities. An attacker could possibly use this issue
to construct a URI with a disallowed scheme that would bypass
sanitization, leading to cross-site scripting. This issue only affected
Ubuntu 18.04 LTS. (CVE-2018-7753)

Yaniv Nizry discovered that Bleach was vulnerable to a mutation
cross-site scripting issue when sanitizing HTML with the noscript tag
and a raw tag in the allowed tags list. An attacker could possibly
use this issue to inject malicious content, leading to cross-site
scripting. This issue only affected Ubuntu 18.04 LTS. (CVE-2020-6802)

Yaniv Nizry discovered that Bleach was vulnerable to a mutation
cross-site scripting issue when sanitizing HTML with RCDATA together
with svg or math tags in the allowed tags list. An attacker could
possibly use this issue to inject malicious content, leading to
cross-site scripting. (CVE-2020-6816)

It was discovered that Bleach incorrectly handled parsing of style
attributes when sanitizing HTML. An attacker could possibly use this
issue to perform a regular expression denial of service, leading to
excessive resource consumption. (CVE-2020-6817)

Yaniv Nizry and Michal Bentkowski discovered that Bleach was vulnerable
to a mutation cross-site scripting issue when sanitizing HTML with
certain combinations of allowed tags. An attacker could possibly use
this issue to inject malicious content, leading to cross-site scripting.
(CVE-2021-23980)");

  script_tag(name:"affected", value:"'python-bleach' package(s) on Ubuntu 16.04, Ubuntu 18.04, Ubuntu 20.04.");

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

if(release == "UBUNTU16.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"python-bleach", ver:"1.4.2-1ubuntu0.1~esm1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python-bleach-doc", ver:"1.4.2-1ubuntu0.1~esm1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python3-bleach", ver:"1.4.2-1ubuntu0.1~esm1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU18.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"python-bleach", ver:"2.1.2-1ubuntu0.1~esm1", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python-bleach-doc", ver:"2.1.2-1ubuntu0.1~esm1", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python3-bleach", ver:"2.1.2-1ubuntu0.1~esm1", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU20.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"python-bleach-doc", ver:"3.1.1-1ubuntu0.1~esm1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python3-bleach", ver:"3.1.1-1ubuntu0.1~esm1", rls:"UBUNTU20.04 LTS"))) {
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
