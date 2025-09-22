# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.842784");
  script_cve_id("CVE-2016-3947", "CVE-2016-4051", "CVE-2016-4052", "CVE-2016-4053", "CVE-2016-4054", "CVE-2016-4553", "CVE-2016-4554", "CVE-2016-4555", "CVE-2016-4556");
  script_tag(name:"creation_date", value:"2016-06-10 03:23:14 +0000 (Fri, 10 Jun 2016)");
  script_version("2024-02-02T05:06:05+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:05 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-04-28 13:50:33 +0000 (Thu, 28 Apr 2016)");

  script_name("Ubuntu: Security Advisory (USN-2995-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(12\.04\ LTS|14\.04\ LTS|15\.10|16\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-2995-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2995-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'squid3' package(s) announced via the USN-2995-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Yuriy M. Kaminskiy discovered that the Squid pinger utility incorrectly
handled certain ICMPv6 packets. A remote attacker could use this issue to
cause Squid to crash, resulting in a denial of service, or possibly cause
Squid to leak information into log files. (CVE-2016-3947)

Yuriy M. Kaminskiy discovered that the Squid cachemgr.cgi tool incorrectly
handled certain crafted data. A remote attacker could use this issue to
cause Squid to crash, resulting in a denial of service, or possibly execute
arbitrary code. (CVE-2016-4051)

It was discovered that Squid incorrectly handled certain Edge Side Includes
(ESI) responses. A remote attacker could possibly use this issue to cause
Squid to crash, resulting in a denial of service, or possibly execute
arbitrary code. (CVE-2016-4052, CVE-2016-4053, CVE-2016-4054)

Jianjun Chen discovered that Squid did not correctly ignore the Host header
when absolute-URI is provided. A remote attacker could possibly use this
issue to conduct cache-poisoning attacks. This issue only affected Ubuntu
14.04 LTS, Ubuntu 15.10 and Ubuntu 16.04 LTS. (CVE-2016-4553)

Jianjun Chen discovered that Squid incorrectly handled certain HTTP Host
headers. A remote attacker could possibly use this issue to conduct
cache-poisoning attacks. (CVE-2016-4554)

It was discovered that Squid incorrectly handled certain Edge Side Includes
(ESI) responses. A remote attacker could possibly use this issue to cause
Squid to crash, resulting in a denial of service. (CVE-2016-4555,
CVE-2016-4556)");

  script_tag(name:"affected", value:"'squid3' package(s) on Ubuntu 12.04, Ubuntu 14.04, Ubuntu 15.10, Ubuntu 16.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"squid-cgi", ver:"3.1.19-1ubuntu3.12.04.7", rls:"UBUNTU12.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squid3", ver:"3.1.19-1ubuntu3.12.04.7", rls:"UBUNTU12.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"squid-cgi", ver:"3.3.8-1ubuntu6.8", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squid3", ver:"3.3.8-1ubuntu6.8", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU15.10") {

  if(!isnull(res = isdpkgvuln(pkg:"squid-cgi", ver:"3.3.8-1ubuntu16.3", rls:"UBUNTU15.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squid3", ver:"3.3.8-1ubuntu16.3", rls:"UBUNTU15.10"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"squid-cgi", ver:"3.5.12-1ubuntu7.2", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squid3", ver:"3.5.12-1ubuntu7.2", rls:"UBUNTU16.04 LTS"))) {
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
