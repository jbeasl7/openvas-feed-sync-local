# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.841924");
  script_cve_id("CVE-2014-3505", "CVE-2014-3506", "CVE-2014-3507", "CVE-2014-3508", "CVE-2014-3509", "CVE-2014-3510", "CVE-2014-3511", "CVE-2014-3512", "CVE-2014-5139");
  script_tag(name:"creation_date", value:"2014-08-08 04:02:31 +0000 (Fri, 08 Aug 2014)");
  script_version("2024-02-02T05:06:05+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:05 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Ubuntu: Security Advisory (USN-2308-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(10\.04\ LTS|12\.04\ LTS|14\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-2308-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2308-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openssl' package(s) announced via the USN-2308-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Adam Langley and Wan-Teh Chang discovered that OpenSSL incorrectly handled
certain DTLS packets. A remote attacker could use this issue to cause
OpenSSL to crash, resulting in a denial of service. (CVE-2014-3505)

Adam Langley discovered that OpenSSL incorrectly handled memory when
processing DTLS handshake messages. A remote attacker could use this issue
to cause OpenSSL to consume memory, resulting in a denial of service.
(CVE-2014-3506)

Adam Langley discovered that OpenSSL incorrectly handled memory when
processing DTLS fragments. A remote attacker could use this issue to cause
OpenSSL to leak memory, resulting in a denial of service. This issue
only affected Ubuntu 12.04 LTS and Ubuntu 14.04 LTS. (CVE-2014-3507)

Ivan Fratric discovered that OpenSSL incorrectly leaked information in
the pretty printing functions. When OpenSSL is used with certain
applications, an attacker may use this issue to possibly gain access to
sensitive information. (CVE-2014-3508)

Gabor Tyukasz discovered that OpenSSL contained a race condition when
processing serverhello messages. A malicious server could use this issue
to cause clients to crash, resulting in a denial of service. This issue
only affected Ubuntu 12.04 LTS and Ubuntu 14.04 LTS. (CVE-2014-3509)

Felix Grobert discovered that OpenSSL incorrectly handled certain DTLS
handshake messages. A malicious server could use this issue to cause
clients to crash, resulting in a denial of service. (CVE-2014-3510)

David Benjamin and Adam Langley discovered that OpenSSL incorrectly
handled fragmented ClientHello messages. If a remote attacker were able to
perform a machine-in-the-middle attack, this flaw could be used to force a
protocol downgrade to TLS 1.0. This issue only affected Ubuntu 12.04 LTS
and Ubuntu 14.04 LTS. (CVE-2014-3511)

Sean Devlin and Watson Ladd discovered that OpenSSL incorrectly handled
certain SRP parameters. A remote attacker could use this with applications
that use SRP to cause a denial of service, or possibly execute arbitrary
code. This issue only affected Ubuntu 12.04 LTS and Ubuntu 14.04 LTS.
(CVE-2014-3512)

Joonas Kuorilehto and Riku Hietamaki discovered that OpenSSL incorrectly
handled certain Server Hello messages that specify an SRP ciphersuite. A
malicious server could use this issue to cause clients to crash, resulting
in a denial of service. This issue only affected Ubuntu 12.04 LTS and
Ubuntu 14.04 LTS. (CVE-2014-5139)");

  script_tag(name:"affected", value:"'openssl' package(s) on Ubuntu 10.04, Ubuntu 12.04, Ubuntu 14.04.");

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

if(release == "UBUNTU10.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"libssl0.9.8", ver:"0.9.8k-7ubuntu8.20", rls:"UBUNTU10.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU12.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"libssl1.0.0", ver:"1.0.1-4ubuntu5.17", rls:"UBUNTU12.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libssl1.0.0", ver:"1.0.1f-1ubuntu2.5", rls:"UBUNTU14.04 LTS"))) {
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
