# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.843256");
  script_cve_id("CVE-2009-5147", "CVE-2015-1855", "CVE-2015-7551", "CVE-2015-9096", "CVE-2016-2337", "CVE-2016-2339", "CVE-2016-7798");
  script_tag(name:"creation_date", value:"2017-07-26 05:16:30 +0000 (Wed, 26 Jul 2017)");
  script_version("2024-02-02T05:06:06+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:06 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-01-11 02:51:48 +0000 (Wed, 11 Jan 2017)");

  script_name("Ubuntu: Security Advisory (USN-3365-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(14\.04\ LTS|16\.04\ LTS|17\.04)");

  script_xref(name:"Advisory-ID", value:"USN-3365-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3365-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ruby1.9.1, ruby2.0, ruby2.3' package(s) announced via the USN-3365-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that Ruby DL::dlopen incorrectly handled opening
libraries. An attacker could possibly use this issue to open libraries with
tainted names. This issue only applied to Ubuntu 14.04 LTS. (CVE-2009-5147)

Tony Arcieri, Jeffrey Walton, and Steffan Ullrich discovered that the Ruby
OpenSSL extension incorrectly handled hostname wildcard matching. This
issue only applied to Ubuntu 14.04 LTS. (CVE-2015-1855)

Christian Hofstaedtler discovered that Ruby Fiddle::Handle incorrectly
handled certain crafted strings. An attacker could use this issue to cause
a denial of service, or possibly execute arbitrary code. This issue only
applied to Ubuntu 14.04 LTS. (CVE-2015-7551)

It was discovered that Ruby Net::SMTP incorrectly handled CRLF sequences. A
remote attacker could possibly use this issue to inject SMTP commands.
(CVE-2015-9096)

Marcin Noga discovered that Ruby incorrectly handled certain arguments in
a TclTkIp class method. An attacker could possibly use this issue to
execute arbitrary code. This issue only affected Ubuntu 14.04 LTS.
(CVE-2016-2337)

It was discovered that Ruby Fiddle::Function.new incorrectly handled
certain arguments. An attacker could possibly use this issue to execute
arbitrary code. This issue only affected Ubuntu 14.04 LTS. (CVE-2016-2339)

It was discovered that Ruby incorrectly handled the initialization vector
(IV) in GCM mode. An attacker could possibly use this issue to bypass
encryption. (CVE-2016-7798)");

  script_tag(name:"affected", value:"'ruby1.9.1, ruby2.0, ruby2.3' package(s) on Ubuntu 14.04, Ubuntu 16.04, Ubuntu 17.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libruby1.9.1", ver:"1.9.3.484-2ubuntu1.3", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libruby2.0", ver:"2.0.0.484-1ubuntu2.4", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ruby1.9.1", ver:"1.9.3.484-2ubuntu1.3", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ruby2.0", ver:"2.0.0.484-1ubuntu2.4", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU16.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"libruby2.3", ver:"2.3.1-2~16.04.2", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ruby2.3", ver:"2.3.1-2~16.04.2", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU17.04") {

  if(!isnull(res = isdpkgvuln(pkg:"libruby2.3", ver:"2.3.3-1ubuntu0.1", rls:"UBUNTU17.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ruby2.3", ver:"2.3.3-1ubuntu0.1", rls:"UBUNTU17.04"))) {
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
