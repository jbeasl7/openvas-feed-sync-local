# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2026.8122.1");
  script_cve_id("CVE-2017-16872", "CVE-2017-16875", "CVE-2018-1000098", "CVE-2018-1000099", "CVE-2020-15260", "CVE-2021-21375", "CVE-2021-32686", "CVE-2021-37706", "CVE-2021-43299", "CVE-2021-43300", "CVE-2021-43301", "CVE-2021-43302", "CVE-2021-43303", "CVE-2026-25994");
  script_tag(name:"creation_date", value:"2026-03-26 04:48:00 +0000 (Thu, 26 Mar 2026)");
  script_version("2026-03-26T06:06:30+0000");
  script_tag(name:"last_modification", value:"2026-03-26 06:06:30 +0000 (Thu, 26 Mar 2026)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2026-02-19 19:23:29 +0000 (Thu, 19 Feb 2026)");

  script_name("Ubuntu: Security Advisory (USN-8122-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(16\.04\ LTS|18\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-8122-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-8122-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'pjproject' package(s) announced via the USN-8122-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Youngsung Kim discovered that PJSIP did not properly parse numeric header
fields in SIP messages. A remote attacker could use this issue to cause
PJSIP to crash, resulting in a denial of service, or possibly execute
arbitrary code. This issue only affected Ubuntu 16.04 LTS. (CVE-2017-16872)

Peter Koletzki discovered that PJSIP did not properly handle certain
connection requests. A remote attacker could possibly use this issue to
cause PJSIP to enter an unrecoverable state and reject further connections,
resulting in a denial of service. This issue only affected Ubuntu 16.04
LTS. (CVE-2017-16875)

Alfred Farrugia, Sandro Gauci, and Kevin Harwell discovered that PJSIP did
not properly parse certain SDP messages. A remote attacker could possibly
use this issue to cause PJSIP to crash, resulting in a denial of service.
This issue only affected Ubuntu 16.04 LTS. (CVE-2018-1000098,
CVE-2018-1000099)

Lauri Vanska discovered that PJSIP did not verify hostnames when reusing
TLS connections. If a remote attacker were able to intercept communication,
this flaw could possibly be exploited to view sensitive information.
(CVE-2020-15260)

It was discovered that PJSIP did not properly handle certain sequences of
SDP messages. A remote attacker could possibly use this issue to cause
PJSIP to crash, resulting in a denial of service. (CVE-2021-21375)

It was discovered that the SSL socket implementation in PJSIP contained a
race condition. A remote attacker could possibly use this issue to cause
PJSIP to crash, resulting in a denial of service. This issue was only
addressed in Ubuntu 18.04 LTS. (CVE-2021-32686)

It was discovered that PJSIP did not properly parse certain STUN messages.
A remote attacker could use this issue to cause PJSIP to crash, resulting
in a denial of service, or possibly execute arbitrary code.
(CVE-2021-37706)

Uriya Yavnieli discovered that PJSIP did not properly manage memory under
certain conditions. A remote attacker could use this issue to cause PJSIP
to crash, resulting in a denial of service, or possibly execute arbitrary
code. (CVE-2021-43299, CVE-2021-43300, CVE-2021-43301, CVE-2021-43302,
CVE-2021-43303)

It was discovered that PJSIP did not properly manage memory when processing
ICE session credentials. A remote attacker could use this issue to cause
PJSIP to crash, resulting in a denial of service, or possibly execute
arbitrary code. (CVE-2026-25994)");

  script_tag(name:"affected", value:"'pjproject' package(s) on Ubuntu 16.04, Ubuntu 18.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libpj2", ver:"2.1.0.0.ast20130823-1+deb8u1ubuntu0.1~esm1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libpjmedia2", ver:"2.1.0.0.ast20130823-1+deb8u1ubuntu0.1~esm1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libpjnath2", ver:"2.1.0.0.ast20130823-1+deb8u1ubuntu0.1~esm1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libpjsip2", ver:"2.1.0.0.ast20130823-1+deb8u1ubuntu0.1~esm1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libpjsua2", ver:"2.1.0.0.ast20130823-1+deb8u1ubuntu0.1~esm1", rls:"UBUNTU16.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libpj2", ver:"2.7.2~dfsg-1ubuntu0.1~esm1", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libpjmedia2", ver:"2.7.2~dfsg-1ubuntu0.1~esm1", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libpjnath2", ver:"2.7.2~dfsg-1ubuntu0.1~esm1", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libpjsip2", ver:"2.7.2~dfsg-1ubuntu0.1~esm1", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libpjsua2", ver:"2.7.2~dfsg-1ubuntu0.1~esm1", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python-pjproject", ver:"2.7.2~dfsg-1ubuntu0.1~esm1", rls:"UBUNTU18.04 LTS"))) {
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
