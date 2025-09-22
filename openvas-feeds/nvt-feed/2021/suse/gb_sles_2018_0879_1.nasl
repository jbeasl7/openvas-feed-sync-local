# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2018.0879.1");
  script_cve_id("CVE-2017-15710", "CVE-2017-15715", "CVE-2018-1283", "CVE-2018-1301", "CVE-2018-1303", "CVE-2018-1312");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-04-23 14:27:29 +0000 (Mon, 23 Apr 2018)");

  script_name("SUSE: Security Advisory (SUSE-SU-2018:0879-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP1)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2018:0879-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2018/suse-su-20180879-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1057406");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1086774");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1086775");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1086813");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1086814");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1086817");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1086820");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2018-April/003875.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'apache2' package(s) announced via the SUSE-SU-2018:0879-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for apache2 fixes the following issues:


 * CVE-2018-1283: when mod_session is configured to forward its session data to CGI applications
 (SessionEnv on, not the default), a remote user may influence their content by
 using a \'Session\' header leading to unexpected behavior [bsc#1086814].

 * CVE-2018-1301: due to an out of bound access after a size limit being reached by reading the HTTP header,
 a specially crafted request could lead to remote denial of service. [bsc#1086817]

 * CVE-2018-1303: a specially crafted HTTP request header could lead to crash due to an out of bound read
 while preparing data to be cached in shared memory.[bsc#1086813]

 * CVE-2017-15715: a regular expression could match '$' to a newline character in a malicious filename,
 rather than matching only the end of the filename. leading to corruption of uploaded files.[bsc#1086774]

 * CVE-2018-1312: when generating an HTTP Digest authentication challenge, the nonce sent to prevent
 reply attacks was not correctly generated using a pseudo-random seed.
 In a cluster of servers using a common Digest authentication configuration,
 HTTP requests could be replayed across servers by an attacker without detection. [bsc#1086775]

 * CVE-2017-15710: mod_authnz_ldap, if configured with AuthLDAPCharsetConfig,
 uses the Accept-Language header value to lookup the right charset encoding when verifying the
 user's credentials. If the header value is not present in the charset conversion table,
 a fallback mechanism is used to truncate it to a two characters value to allow a quick retry
 (for example, 'en-US' is truncated to 'en').
 A header value of less than two characters forces an out of bound write of one NUL byte to a
 memory location that is not part of the string. In the worst case, quite unlikely, the process
 would crash which could be used as a Denial of Service attack. In the more likely case, this memory
 is already reserved for future use and the issue has no effect at all. [bsc#1086820]

 * gensslcert: fall back to 'localhost' as hostname [bsc#1057406]");

  script_tag(name:"affected", value:"'apache2' package(s) on SUSE Linux Enterprise Server 12-SP1, SUSE Linux Enterprise Server for SAP Applications 12-SP1.");

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

if(release == "SLES12.0SP1") {

  if(!isnull(res = isrpmvuln(pkg:"apache2", rpm:"apache2~2.4.16~20.16.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apache2-doc", rpm:"apache2-doc~2.4.16~20.16.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apache2-example-pages", rpm:"apache2-example-pages~2.4.16~20.16.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apache2-prefork", rpm:"apache2-prefork~2.4.16~20.16.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apache2-utils", rpm:"apache2-utils~2.4.16~20.16.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apache2-worker", rpm:"apache2-worker~2.4.16~20.16.1", rls:"SLES12.0SP1"))) {
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
