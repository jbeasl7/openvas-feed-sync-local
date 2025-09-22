# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.123219");
  script_cve_id("CVE-2012-6657", "CVE-2014-3673", "CVE-2014-3687", "CVE-2014-3688", "CVE-2014-5471", "CVE-2014-5472", "CVE-2014-6410", "CVE-2014-9322");
  script_tag(name:"creation_date", value:"2015-10-06 11:00:52 +0000 (Tue, 06 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-14 18:23:00 +0000 (Fri, 14 Aug 2020)");

  script_name("Oracle: Security Advisory (ELSA-2014-1997)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux6");

  script_xref(name:"Advisory-ID", value:"ELSA-2014-1997");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2014-1997.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel' package(s) announced via the ELSA-2014-1997 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[2.6.32-504.3.3]
- [x86] traps: stop using IST for #SS (Petr Matousek) [1172810 1172811] {CVE-2014-9322}

[2.6.32-504.3.2]
- [md] dm-thin: fix pool_io_hints to avoid looking at max_hw_sectors (Mike Snitzer) [1161420 1161421 1142773 1145230]

[2.6.32-504.3.1]
- [s390] zcrypt: toleration of new crypto adapter hardware (Hendrik Brueckner) [1158311 1134984]
- [s390] zcrypt: support for extended number of ap domains (Hendrik Brueckner) [1158311 1134984]
- [md] dm-thin: fix potential for infinite loop in pool_io_hints (Mike Snitzer) [1161420 1161421 1142773 1145230]

[2.6.32-504.2.1]
- [fs] udf: Avoid infinite loop when processing indirect ICBs (Jacob Tanenbaum) [1142319 1142320] {CVE-2014-6410}
- [fs] isofs: unbound recursion when processing relocated directories (Jacob Tanenbaum) [1142268 1142269] {CVE-2014-5472 CVE-2014-5471}
- [net] ipv6: delete expired route in ip6_pmtu_deliver (Hannes Frederic Sowa) [1161418 1156137]
- [net] sctp: fix remote memory pressure from excessive queueing (Daniel Borkmann) [1155746 1154676] {CVE-2014-3688}
- [net] sctp: fix panic on duplicate ASCONF chunks (Daniel Borkmann) [1155733 1154676] {CVE-2014-3687}
- [net] sctp: fix skb_over_panic when receiving malformed ASCONF chunks (Daniel Borkmann) [1147857 1154676] {CVE-2014-3673}
- [net] sctp: handle association restarts when the socket is closed (Daniel Borkmann) [1147857 1154676]
- [md] dm-thin: refactor requeue_io to eliminate spinlock bouncing (Mike Snitzer) [1161420 1161421 1142773 1145230]
- [md] dm-thin: optimize retry_bios_on_resume (Mike Snitzer) [1161420 1161421 1142773 1145230]
- [md] dm-thin: sort the deferred cells (Mike Snitzer) [1161420 1161421 1142773 1145230]
- [md] dm-thin: direct dispatch when breaking sharing (Mike Snitzer) [1161420 1161421 1142773 1145230]
- [md] dm-thin: remap the bios in a cell immediately (Mike Snitzer) [1161420 1161421 1142773 1145230]
- [md] dm-thin: defer whole cells rather than individual bios (Mike Snitzer) [1161420 1161421 1142773 1145230]
- [md] dm-thin: factor out remap_and_issue_overwrite (Mike Snitzer) [1161420 1161421 1142773 1145230]
- [md] dm-thin: performance improvement to discard processing (Mike Snitzer) [1161420 1161421 1142773 1145230]
- [md] dm-thin: grab a virtual cell before looking up the mapping (Mike Snitzer) [1161420 1161421 1142773 1145230]
- [md] dm-thin: implement thin_merge (Mike Snitzer) [1161420 1161421 1142773 1145230]
- [md] dm: improve documentation and code clarity in dm_merge_bvec (Mike Snitzer) [1161420 1161421 1142773 1145230]
- [md] dm-thin: adjust max_sectors_kb based on thinp blocksize (Mike Snitzer) [1161420 1161421 1142773 1145230]
- [md] block: fix alignment_offset math that assumes io_min is a power-of-2 (Mike Snitzer) [1161420 1161421 1142773 1145230]
- [md] dm-thin: throttle incoming IO (Mike Snitzer) [1161420 1161421 1142773 1145230]
- [md] dm-thin: prefetch missing metadata pages (Mike Snitzer) [1161420 ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'kernel' package(s) on Oracle Linux 6.");

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

if(release == "OracleLinux6") {

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.32~504.3.3.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-abi-whitelists", rpm:"kernel-abi-whitelists~2.6.32~504.3.3.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.32~504.3.3.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~2.6.32~504.3.3.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~2.6.32~504.3.3.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.32~504.3.3.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware", rpm:"kernel-firmware~2.6.32~504.3.3.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~2.6.32~504.3.3.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perf", rpm:"perf~2.6.32~504.3.3.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-perf", rpm:"python-perf~2.6.32~504.3.3.el6", rls:"OracleLinux6"))) {
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
