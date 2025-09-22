# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2018.0293.1");
  script_cve_id("CVE-2017-14919", "CVE-2017-15896", "CVE-2017-3735", "CVE-2017-3736", "CVE-2017-3737", "CVE-2017-3738");
  script_tag(name:"creation_date", value:"2021-06-09 14:57:48 +0000 (Wed, 09 Jun 2021)");
  script_version("2024-02-02T14:37:49+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:49 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-12-29 14:34:44 +0000 (Fri, 29 Dec 2017)");

  script_name("SUSE: Security Advisory (SUSE-SU-2018:0293-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2018:0293-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2018/suse-su-20180293-1/");
  script_xref(name:"URL", value:"https://nodejs.org/en/blog/vulnerability/december-2017-security-releases/");
  script_xref(name:"URL", value:"https://nodejs.org/en/blog/release/v6.12.2/");
  script_xref(name:"URL", value:"https://nodejs.org/en/blog/release/v6.12.1/");
  script_xref(name:"URL", value:"https://nodejs.org/en/blog/release/v6.12.0/");
  script_xref(name:"URL", value:"https://nodejs.org/en/blog/release/v6.11.5/");
  script_xref(name:"URL", value:"https://nodejs.org/en/blog/release/v6.11.4/");
  script_xref(name:"URL", value:"https://nodejs.org/en/blog/release/v6.11.3/");
  script_xref(name:"URL", value:"https://nodejs.org/en/blog/release/v6.11.2/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'nodejs6' package(s) announced via the SUSE-SU-2018:0293-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for nodejs6 fixes the following issues:
Security issues fixed:
- CVE-2017-15896: Vulnerable to CVE-2017-3737 due to embedded OpenSSL
 (bsc#1072322).
- CVE-2017-14919: Embedded zlib issue could cause a DoS via specific
 windowBits value.
- CVE-2017-3738: Embedded OpenSSL is vulnerable to rsaz_1024_mul_avx2
 overflow bug on x86_64.
- CVE-2017-3736: Embedded OpenSSL is vulnerable to bn_sqrx8x_internal
 carry bug on x86_64 (bsc#1066242).
- CVE-2017-3735: Embedded OpenSSL is vulnerable to malformed X.509
 IPAdressFamily that could cause OOB read (bsc#1056058).
Bug fixes:
- Update to LTS release 6.12.2 (bsc#1072322):
 *
[link moved to references]
 * [link moved to references]
 * [link moved to references]
 * [link moved to references]
 * [link moved to references]
 * [link moved to references]
 * [link moved to references]
 * [link moved to references]");

  script_tag(name:"affected", value:"'nodejs6' package(s) on SUSE Enterprise Storage 4, SUSE Linux Enterprise Module for Web Scripting 12, SUSE OpenStack Cloud 7.");

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

if(release == "SLES12.0") {

  if(!isnull(res = isrpmvuln(pkg:"nodejs6", rpm:"nodejs6~6.12.2~11.8.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs6-debuginfo", rpm:"nodejs6-debuginfo~6.12.2~11.8.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs6-debugsource", rpm:"nodejs6-debugsource~6.12.2~11.8.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs6-devel", rpm:"nodejs6-devel~6.12.2~11.8.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs6-docs", rpm:"nodejs6-docs~6.12.2~11.8.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"npm6", rpm:"npm6~6.12.2~11.8.1", rls:"SLES12.0"))) {
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
