# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2025.7729.1");
  script_cve_id("CVE-2017-17689", "CVE-2019-10732", "CVE-2020-11880", "CVE-2024-50624");
  script_tag(name:"creation_date", value:"2025-09-04 04:07:10 +0000 (Thu, 04 Sep 2025)");
  script_version("2025-09-04T05:39:49+0000");
  script_tag(name:"last_modification", value:"2025-09-04 05:39:49 +0000 (Thu, 04 Sep 2025)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-04-29 19:18:09 +0000 (Wed, 29 Apr 2020)");

  script_name("Ubuntu: Security Advisory (USN-7729-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(14\.04\ LTS|16\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-7729-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-7729-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kdepim' package(s) announced via the USN-7729-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Damian Poddebniak, Christian Dresen, Jens Muller, Fabian Ising,
Sebastian Schinzel, Simon Friedberger, Juraj Somorovsky, and Jorg
Schwenk discovered that the KMail application of KDE PIM could be made
to leak the plaintext of S/MIME encrypted emails when retrieving
external content in emails. Under certain configurations, if a user were
tricked into opening a specially crafted email, an attacker could
possibly use this issue to obtain the plaintext of an encrypted email.
This update mitigates the issue by preventing KMail from automatically
loading external content. (CVE-2017-17689)

Jens Muller, Marcus Brinkmann, Damian Poddebniak, Sebastian Schinzel,
and Jorg Schwenk discovered that the KMail application of KDE PIM could
be made to leak the plaintext of S/MIME or PGP encrypted emails. If a
user were tricked into replying to a specially crafted email, an
attacker could possibly use this issue to obtain the plaintext of an
encrypted email. (CVE-2019-10732)

It was discovered that the KMail application of KDE PIM could be made to
attach files to an email without the user's knowledge. If a user
were tricked into sending an email created by a specially crafted
'mailto' link, an attacker could possibly use this issue to obtain
sensitive files. This update mitigates the issue by displaying a
warning to the user when files are attached in this way.
(CVE-2020-11880)

It was discovered that the Account Wizard application of KDE PIM used
HTTP rather than HTTPS when retrieving certain email server
configurations. An attacker could possibly use this issue to cause email
clients to use an attacker-controlled email server. This issue only
affected Ubuntu 16.04 LTS. (CVE-2024-50624)");

  script_tag(name:"affected", value:"'kdepim' package(s) on Ubuntu 14.04, Ubuntu 16.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"kmail", ver:"4:4.13.3-0ubuntu0.2+esm1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmessageviewer4", ver:"4:4.13.3-0ubuntu0.2+esm1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libtemplateparser4", ver:"4:4.13.3-0ubuntu0.2+esm1", rls:"UBUNTU14.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"accountwizard", ver:"4:15.12.3-0ubuntu1.1+esm1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kmail", ver:"4:15.12.3-0ubuntu1.1+esm1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libkf5messageviewer5", ver:"4:15.12.3-0ubuntu1.1+esm1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libkf5templateparser5", ver:"4:15.12.3-0ubuntu1.1+esm1", rls:"UBUNTU16.04 LTS"))) {
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
