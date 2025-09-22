# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.843238");
  script_cve_id("CVE-2016-2519", "CVE-2016-7426", "CVE-2016-7427", "CVE-2016-7428", "CVE-2016-7429", "CVE-2016-7431", "CVE-2016-7433", "CVE-2016-7434", "CVE-2016-9042", "CVE-2016-9310", "CVE-2016-9311", "CVE-2017-6458", "CVE-2017-6460", "CVE-2017-6462", "CVE-2017-6463", "CVE-2017-6464");
  script_tag(name:"creation_date", value:"2017-07-14 10:24:52 +0000 (Fri, 14 Jul 2017)");
  script_version("2024-02-02T05:06:06+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:06 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-03-29 18:24:37 +0000 (Wed, 29 Mar 2017)");

  script_name("Ubuntu: Security Advisory (USN-3349-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(14\.04\ LTS|16\.04\ LTS|16\.10|17\.04)");

  script_xref(name:"Advisory-ID", value:"USN-3349-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3349-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ntp' package(s) announced via the USN-3349-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Yihan Lian discovered that NTP incorrectly handled certain large request
data values. A remote attacker could possibly use this issue to cause NTP
to crash, resulting in a denial of service. This issue only affected
Ubuntu 16.04 LTS. (CVE-2016-2519)

Miroslav Lichvar discovered that NTP incorrectly handled certain spoofed
addresses when performing rate limiting. A remote attacker could possibly
use this issue to perform a denial of service. This issue only affected
Ubuntu 14.04 LTS, Ubuntu 16.04 LTS, and Ubuntu 16.10. (CVE-2016-7426)

Matthew Van Gundy discovered that NTP incorrectly handled certain crafted
broadcast mode packets. A remote attacker could possibly use this issue to
perform a denial of service. This issue only affected Ubuntu 14.04 LTS,
Ubuntu 16.04 LTS, and Ubuntu 16.10. (CVE-2016-7427, CVE-2016-7428)

Miroslav Lichvar discovered that NTP incorrectly handled certain responses.
A remote attacker could possibly use this issue to perform a denial of
service. This issue only affected Ubuntu 14.04 LTS, Ubuntu 16.04 LTS, and
Ubuntu 16.10. (CVE-2016-7429)

Sharon Goldberg and Aanchal Malhotra discovered that NTP incorrectly
handled origin timestamps of zero. A remote attacker could possibly use
this issue to bypass the origin timestamp protection mechanism. This issue
only affected Ubuntu 16.10. (CVE-2016-7431)

Brian Utterback, Sharon Goldberg and Aanchal Malhotra discovered that NTP
incorrectly performed initial sync calculations. This issue only applied
to Ubuntu 16.04 LTS and Ubuntu 16.10. (CVE-2016-7433)

Magnus Stubman discovered that NTP incorrectly handled certain mrulist
queries. A remote attacker could possibly use this issue to cause NTP to
crash, resulting in a denial of service. This issue only affected Ubuntu
16.04 LTS and Ubuntu 16.10. (CVE-2016-7434)

Matthew Van Gund discovered that NTP incorrectly handled origin timestamp
checks. A remote attacker could possibly use this issue to perform a denial
of service. This issue only affected Ubuntu Ubuntu 16.10, and Ubuntu 17.04.
(CVE-2016-9042)

Matthew Van Gundy discovered that NTP incorrectly handled certain control
mode packets. A remote attacker could use this issue to set or unset traps.
This issue only applied to Ubuntu 14.04 LTS, Ubuntu 16.04 LTS and Ubuntu
16.10. (CVE-2016-9310)

Matthew Van Gundy discovered that NTP incorrectly handled the trap service.
A remote attacker could possibly use this issue to cause NTP to crash,
resulting in a denial of service. This issue only applied to Ubuntu 14.04
LTS, Ubuntu 16.04 LTS and Ubuntu 16.10. (CVE-2016-9311)

It was discovered that NTP incorrectly handled memory when processing long
variables. A remote authenticated user could possibly use this issue to
cause NTP to crash, resulting in a denial of service. (CVE-2017-6458)

It was discovered that NTP incorrectly handled memory when processing long
variables. A remote authenticated user could possibly ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'ntp' package(s) on Ubuntu 14.04, Ubuntu 16.04, Ubuntu 16.10, Ubuntu 17.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"ntp", ver:"1:4.2.6.p5+dfsg-3ubuntu2.14.04.11", rls:"UBUNTU14.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"ntp", ver:"1:4.2.8p4+dfsg-3ubuntu5.5", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU16.10") {

  if(!isnull(res = isdpkgvuln(pkg:"ntp", ver:"1:4.2.8p8+dfsg-1ubuntu2.1", rls:"UBUNTU16.10"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"ntp", ver:"1:4.2.8p9+dfsg-2ubuntu1.1", rls:"UBUNTU17.04"))) {
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
