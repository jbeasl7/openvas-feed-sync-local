# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.842905");
  script_cve_id("CVE-2015-7973", "CVE-2015-7974", "CVE-2015-7975", "CVE-2015-7976", "CVE-2015-7977", "CVE-2015-7978", "CVE-2015-7979", "CVE-2015-8138", "CVE-2015-8158", "CVE-2016-0727", "CVE-2016-1547", "CVE-2016-1548", "CVE-2016-1550", "CVE-2016-2516", "CVE-2016-2518", "CVE-2016-4954", "CVE-2016-4955", "CVE-2016-4956");
  script_tag(name:"creation_date", value:"2016-10-06 04:56:04 +0000 (Thu, 06 Oct 2016)");
  script_version("2024-02-02T05:06:06+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:06 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-04-20 16:34:09 +0000 (Thu, 20 Apr 2017)");

  script_name("Ubuntu: Security Advisory (USN-3096-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(12\.04\ LTS|14\.04\ LTS|16\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-3096-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3096-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ntp' package(s) announced via the USN-3096-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Aanchal Malhotra discovered that NTP incorrectly handled authenticated
broadcast mode. A remote attacker could use this issue to perform a replay
attack. (CVE-2015-7973)

Matt Street discovered that NTP incorrectly verified peer associations of
symmetric keys. A remote attacker could use this issue to perform an
impersonation attack. (CVE-2015-7974)

Jonathan Gardner discovered that the NTP ntpq utility incorrectly handled
memory. An attacker could possibly use this issue to cause ntpq to crash,
resulting in a denial of service. This issue only affected Ubuntu 16.04
LTS. (CVE-2015-7975)

Jonathan Gardner discovered that the NTP ntpq utility incorrectly handled
dangerous characters in filenames. An attacker could possibly use this
issue to overwrite arbitrary files. (CVE-2015-7976)

Stephen Gray discovered that NTP incorrectly handled large restrict lists.
An attacker could use this issue to cause NTP to crash, resulting in a
denial of service. (CVE-2015-7977, CVE-2015-7978)

Aanchal Malhotra discovered that NTP incorrectly handled authenticated
broadcast mode. A remote attacker could use this issue to cause NTP to
crash, resulting in a denial of service. (CVE-2015-7979)

Jonathan Gardner discovered that NTP incorrectly handled origin timestamp
checks. A remote attacker could use this issue to spoof peer servers.
(CVE-2015-8138)

Jonathan Gardner discovered that the NTP ntpq utility did not properly
handle certain incorrect values. An attacker could possibly use this issue
to cause ntpq to hang, resulting in a denial of service. (CVE-2015-8158)

It was discovered that the NTP cronjob incorrectly cleaned up the
statistics directory. A local attacker could possibly use this to escalate
privileges. (CVE-2016-0727)

Stephen Gray and Matthew Van Gundy discovered that NTP incorrectly
validated crypto-NAKs. A remote attacker could possibly use this issue to
prevent clients from synchronizing. (CVE-2016-1547)

Miroslav Lichvar and Jonathan Gardner discovered that NTP incorrectly
handled switching to interleaved symmetric mode. A remote attacker could
possibly use this issue to prevent clients from synchronizing.
(CVE-2016-1548)

Matthew Van Gundy, Stephen Gray and Loganaden Velvindron discovered that
NTP incorrectly handled message authentication. A remote attacker could
possibly use this issue to recover the message digest key. (CVE-2016-1550)

Yihan Lian discovered that NTP incorrectly handled duplicate IPs on
unconfig directives. An authenticated remote attacker could possibly use
this issue to cause NTP to crash, resulting in a denial of service.
(CVE-2016-2516)

Yihan Lian discovered that NTP incorrectly handled certail peer
associations. A remote attacker could possibly use this issue to cause NTP
to crash, resulting in a denial of service. (CVE-2016-2518)

Jakub Prokes discovered that NTP incorrectly handled certain spoofed
packets. A remote attacker could possibly use ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'ntp' package(s) on Ubuntu 12.04, Ubuntu 14.04, Ubuntu 16.04.");

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

if(release == "UBUNTU12.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"ntp", ver:"1:4.2.6.p3+dfsg-1ubuntu3.11", rls:"UBUNTU12.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU14.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"ntp", ver:"1:4.2.6.p5+dfsg-3ubuntu2.14.04.10", rls:"UBUNTU14.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"ntp", ver:"1:4.2.8p4+dfsg-3ubuntu5.3", rls:"UBUNTU16.04 LTS"))) {
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
