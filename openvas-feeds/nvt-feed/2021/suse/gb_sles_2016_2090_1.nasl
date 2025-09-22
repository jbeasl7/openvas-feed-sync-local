# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2016.2090.1");
  script_cve_id("CVE-2016-5387");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-07-19 13:34:01 +0000 (Tue, 19 Jul 2016)");

  script_name("SUSE: Security Advisory (SUSE-SU-2016:2090-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2016:2090-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2016/suse-su-20162090-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/951692");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/970391");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/973381");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/988488");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2016-August/002213.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'apache2' package(s) announced via the SUSE-SU-2016:2090-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for apache2 fixes the following issues:

- It used to be possible to set an arbitrary $HTTP_PROXY environment variable for
 request handlers -- like CGI scripts -- by including a specially crafted HTTP
 header in the request (CVE-2016-5387). As a result, these server components
 would potentially direct all their outgoing HTTP traffic through a malicious
 proxy server. This patch fixes the issue: the updated Apache server ignores
 such HTTP headers and never sets $HTTP_PROXY for sub-processes (unless a value
 has been explicitly configured by the administrator in the configuration file).
 (bsc#988488)

- Ignore SIGINT signal in child processes. This fixes a race condition in
 signals handling when httpd is running on foreground and the user hits ctrl+c.
 (bsc#970391)

- Don't put the backend in error state (by default) when 500/503 is overridden.
 (bsc#951692)

- Remove obsolete /usr/share/apache2/rc.apache2 sample script. (bsc#973381)");

  script_tag(name:"affected", value:"'apache2' package(s) on SUSE Linux Enterprise Server 12, SUSE Linux Enterprise Server for SAP Applications 12.");

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

  if(!isnull(res = isrpmvuln(pkg:"apache2", rpm:"apache2~2.4.10~14.17.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apache2-doc", rpm:"apache2-doc~2.4.10~14.17.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apache2-example-pages", rpm:"apache2-example-pages~2.4.10~14.17.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apache2-prefork", rpm:"apache2-prefork~2.4.10~14.17.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apache2-utils", rpm:"apache2-utils~2.4.10~14.17.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apache2-worker", rpm:"apache2-worker~2.4.10~14.17.1", rls:"SLES12.0"))) {
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
