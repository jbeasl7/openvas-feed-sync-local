# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2026.8132.1");
  script_cve_id("CVE-2016-4068", "CVE-2016-4069", "CVE-2016-9920", "CVE-2017-6820", "CVE-2017-8114", "CVE-2018-1000071", "CVE-2018-19205", "CVE-2018-19206", "CVE-2018-9846", "CVE-2019-10740");
  script_tag(name:"creation_date", value:"2026-04-01 04:57:46 +0000 (Wed, 01 Apr 2026)");
  script_version("2026-04-01T06:13:16+0000");
  script_tag(name:"last_modification", value:"2026-04-01 06:13:16 +0000 (Wed, 01 Apr 2026)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-05-24 17:12:22 +0000 (Thu, 24 May 2018)");

  script_name("Ubuntu: Security Advisory (USN-8132-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(16\.04\ LTS|18\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-8132-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-8132-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'roundcube' package(s) announced via the USN-8132-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that Roundcube Webmail did not properly sanitize
certain HTML elements within the e-mail body. An attacker could possibly
use this issue to cause a cross-site scripting attack. This issue was only
addressed in Ubuntu 16.04 LTS. (CVE-2016-4068, CVE-2016-4069)

It was discovered that Roundcube Webmail did not properly handle certain
configuration parameters. An attacker could possibly use this issue to
execute arbitrary code. This issue was only addressed in Ubuntu 16.04 LTS.
(CVE-2016-9920)

It was discovered that Roundcube Webmail did not properly sanitize CSS styles
within SVG documents. An attacker could possibly use this issue to cause
a cross-site scripting attack. This issue was only addressed in Ubuntu 16.04 LTS.
(CVE-2017-6820)

It was discovered that Roundcube Webmail did not properly restrict exec call in
certain drivers of the password plugin. An authenticated user could possibly
use this issue to perform arbitrary password resets. This issue was only addressed in
Ubuntu 16.04 LTS. (CVE-2017-8114)

It was discovered that Roundcube Webmail did not properly set file permissions within
the Enigma plugin. An attacker could possibly use this issue to exfiltrate GPG private
keys via network connectivity. (CVE-2018-1000071)

It was discovered that Roundcube Webmail did not properly handle GnuPG MDC
integrity-protection warnings. An attacker could possibly use this issue to obtain
sensitive information from encrypted communications. (CVE-2018-19205)

It was discovered that Roundcube Webmail did not properly sanitize <svg> and <style>
tags within HTML attachments. An attacker could possibly use this issue to cause a
cross-site scripting attack. (CVE-2018-19206)

It was discovered that Roundcube Webmail did not properly handle partially encrypted
multipart messages. An attacker could possibly use this issue to cause
leaking of the plaintext of encrypted messages via an email reply. (CVE-2019-10740)

It was discovered that Roundcube Webmail did not properly sanitize a certain parameter
within the archive plugin. An attacker could possibly use this issue to perform an
IMAP injection attack. This issue was only addressed in Ubuntu 16.04 LTS. (CVE-2018-9846)");

  script_tag(name:"affected", value:"'roundcube' package(s) on Ubuntu 16.04, Ubuntu 18.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"roundcube-core", ver:"1.2~beta+dfsg.1-0ubuntu1+esm7", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"roundcube-plugins", ver:"1.2~beta+dfsg.1-0ubuntu1+esm7", rls:"UBUNTU16.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"roundcube-core", ver:"1.3.6+dfsg.1-1ubuntu0.1~esm7", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"roundcube-plugins", ver:"1.3.6+dfsg.1-1ubuntu0.1~esm7", rls:"UBUNTU18.04 LTS"))) {
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
