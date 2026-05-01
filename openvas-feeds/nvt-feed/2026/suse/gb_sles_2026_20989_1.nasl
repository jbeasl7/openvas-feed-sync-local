# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2026.20989.1");
  script_cve_id("CVE-2025-11232", "CVE-2026-3608");
  script_tag(name:"creation_date", value:"2026-04-13 05:04:44 +0000 (Mon, 13 Apr 2026)");
  script_version("2026-04-13T06:24:05+0000");
  script_tag(name:"last_modification", value:"2026-04-13 06:24:05 +0000 (Mon, 13 Apr 2026)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2026-03-25 09:16:25 +0000 (Wed, 25 Mar 2026)");

  script_name("SUSE: Security Advisory (SUSE-SU-2026:20989-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES16\.0\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2026:20989-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2026/suse-su-202620989-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1252863");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1260380");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-updates/2026-April/045342.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kea' package(s) announced via the SUSE-SU-2026:20989-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for kea fixes the following issues:

Update to 3.0.3:

- CVE-2025-11232: invalid characters cause assert (bsc#1252863).
- CVE-2026-3608: stack overflow via maliciously crafted message (bsc#1260380).

Changelog:

 * A large number of bracket pairs in a JSON payload directed to
 any endpoint would result in a stack overflow, due to recursive
 calls when parsing the JSON. This has been fixed.
 (CVE-2026-3608)
 [bsc#1260380]
 * When a hostname or FQDN received from a client is reduced to an
 empty string by hostname sanitizing, kea-dhcp4 and kea-dhcp6
 will now drop the option.
 (CVE-2025-11232)
 [bsc#1252863]
 * A null dereference is now no longer possible when configuring
 the Control Agent with a socket that lacks the mandatory
 socket-name entry.
 * UNIX sockets are now created as group-writable.
 * Removed logging an error in ping check hook library if using
 lease cache treshold.
 * Fixed deadlock in ping-check hooks library.
 * Fixed a data race in ping-check hooks library.");

  script_tag(name:"affected", value:"'kea' package(s) on SUSE Linux Enterprise Server 16.0, SUSE Linux Enterprise Server for SAP Applications 16.0.");

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

if(release == "SLES16.0.0") {

  if(!isnull(res = isrpmvuln(pkg:"kea", rpm:"kea~3.0.3~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kea-devel", rpm:"kea-devel~3.0.3~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kea-doc", rpm:"kea-doc~3.0.3~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kea-hooks", rpm:"kea-hooks~3.0.3~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkea-asiodns62", rpm:"libkea-asiodns62~3.0.3~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkea-asiolink88", rpm:"libkea-asiolink88~3.0.3~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkea-cc83", rpm:"libkea-cc83~3.0.3~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkea-cfgrpt3", rpm:"libkea-cfgrpt3~3.0.3~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkea-config84", rpm:"libkea-config84~3.0.3~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkea-cryptolink64", rpm:"libkea-cryptolink64~3.0.3~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkea-d2srv63", rpm:"libkea-d2srv63~3.0.3~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkea-database76", rpm:"libkea-database76~3.0.3~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkea-dhcp109", rpm:"libkea-dhcp109~3.0.3~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkea-dhcp_ddns68", rpm:"libkea-dhcp_ddns68~3.0.3~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkea-dhcpsrv131", rpm:"libkea-dhcpsrv131~3.0.3~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkea-dns71", rpm:"libkea-dns71~3.0.3~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkea-eval84", rpm:"libkea-eval84~3.0.3~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkea-exceptions45", rpm:"libkea-exceptions45~3.0.3~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkea-hooks121", rpm:"libkea-hooks121~3.0.3~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkea-http87", rpm:"libkea-http87~3.0.3~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkea-log-interprocess3", rpm:"libkea-log-interprocess3~3.0.3~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkea-log75", rpm:"libkea-log75~3.0.3~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkea-mysql88", rpm:"libkea-mysql88~3.0.3~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkea-pgsql88", rpm:"libkea-pgsql88~3.0.3~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkea-process91", rpm:"libkea-process91~3.0.3~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkea-stats53", rpm:"libkea-stats53~3.0.3~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkea-tcp33", rpm:"libkea-tcp33~3.0.3~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkea-util-io12", rpm:"libkea-util-io12~3.0.3~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkea-util102", rpm:"libkea-util102~3.0.3~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-kea", rpm:"python3-kea~3.0.3~160000.1.1", rls:"SLES16.0.0"))) {
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
