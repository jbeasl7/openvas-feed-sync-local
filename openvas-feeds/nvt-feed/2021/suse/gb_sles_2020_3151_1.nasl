# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2020.3151.1");
  script_cve_id("CVE-2014-3577", "CVE-2015-5262");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");

  script_name("SUSE: Security Advisory (SUSE-SU-2020:3151-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP1|SLES15\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2020:3151-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2020/suse-su-20203151-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1178171");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/945190");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2020-November/007690.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'apache-commons-httpclient' package(s) announced via the SUSE-SU-2020:3151-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for apache-commons-httpclient fixes the following issues:

- http/conn/ssl/SSLConnectionSocketFactory.java ignores the
 http.socket.timeout configuration setting during an SSL handshake,
 which allows remote attackers to cause a denial of service (HTTPS
 call hang) via unspecified vectors. [bsc#945190, CVE-2015-5262]
- org.apache.http.conn.ssl.AbstractVerifier does not properly
 verify that the server hostname matches a domain name in the
 subject's Common Name (CN) or subjectAltName field of the X.509
 certificate, which allows MITM attackers to spoof SSL servers
 via a 'CN=' string in a field in the distinguished name (DN)
 of a certificate. [bsc#1178171, CVE-2014-3577]");

  script_tag(name:"affected", value:"'apache-commons-httpclient' package(s) on SUSE Linux Enterprise Server 15, SUSE Linux Enterprise Server for SAP Applications 15.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "SLES15.0SP1") {

  if(!isnull(res = isrpmvuln(pkg:"apache-commons-httpclient", rpm:"apache-commons-httpclient~3.1~4.3.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES15.0") {

  if(!isnull(res = isrpmvuln(pkg:"apache-commons-httpclient", rpm:"apache-commons-httpclient~3.1~4.3.2", rls:"SLES15.0"))) {
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
