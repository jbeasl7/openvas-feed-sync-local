# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2021.1652.1");
  script_cve_id("CVE-2021-21309", "CVE-2021-29477", "CVE-2021-29478");
  script_tag(name:"creation_date", value:"2021-06-09 14:56:38 +0000 (Wed, 09 Jun 2021)");
  script_version("2024-02-02T14:37:50+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:50 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-05-18 13:33:57 +0000 (Tue, 18 May 2021)");

  script_name("SUSE: Security Advisory (SUSE-SU-2021:1652-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP2|SLES15\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2021:1652-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2021/suse-su-20211652-1/");
  script_xref(name:"URL", value:"https://github.com/redis/redis/issues/7284");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'redis' package(s) announced via the SUSE-SU-2021:1652-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for redis fixes the following issues:

redis was updated to 6.0.13:

CVE-2021-29477: Integer overflow in STRALGO LCS command (bsc#1185729)

CVE-2021-29478: Integer overflow in COPY command for large intsets
 (bsc#1185730)

Cluster: Skip unnecessary check which may prevent failure detection

Fix performance regression in BRPOP on Redis 6.0

Fix edge-case when a module client is unblocked

redis 6.0.12:

Fix compilation error on non-glibc systems if jemalloc is not used

redis 6.0.11:

CVE-2021-21309: Avoid 32-bit overflows when proto-max-bulk-len is set
 high (bsc#1182657)

Fix handling of threaded IO and CLIENT PAUSE (failover), could lead to
 data loss or a crash

Fix the selection of a random element from large hash tables

Fix broken protocol in client tracking tracking-redir-broken message

XINFO able to access expired keys on a replica

Fix broken protocol in redis-benchmark when used with -a or
 --dbnum

Avoid assertions (on older kernels) when testing arm64 CoW bug

CONFIG REWRITE should honor umask settings

Fix firstkey,lastkey,step in COMMAND command for some commands

RM_ZsetRem: Delete key if empty, the bug could leave empty zset keys

Switch systemd type of the sentinel service from notify to simple. This
 can be reverted when updating to 6.2 which fixes
 [link moved to references] .");

  script_tag(name:"affected", value:"'redis' package(s) on SUSE Linux Enterprise Module for Server Applications 15-SP2, SUSE Linux Enterprise Module for Server Applications 15-SP3.");

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

if(release == "SLES15.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"redis", rpm:"redis~6.0.13~1.10.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"redis-debuginfo", rpm:"redis-debuginfo~6.0.13~1.10.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"redis-debugsource", rpm:"redis-debugsource~6.0.13~1.10.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES15.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"redis", rpm:"redis~6.0.13~1.10.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"redis-debuginfo", rpm:"redis-debuginfo~6.0.13~1.10.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"redis-debugsource", rpm:"redis-debugsource~6.0.13~1.10.1", rls:"SLES15.0SP3"))) {
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
