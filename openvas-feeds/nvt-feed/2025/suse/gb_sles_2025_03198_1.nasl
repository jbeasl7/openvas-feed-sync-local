# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2025.03198.1");
  script_cve_id("CVE-2024-6874", "CVE-2025-0665", "CVE-2025-10148", "CVE-2025-4947", "CVE-2025-5025", "CVE-2025-5399", "CVE-2025-9086");
  script_tag(name:"creation_date", value:"2025-09-15 04:11:52 +0000 (Mon, 15 Sep 2025)");
  script_version("2025-09-15T05:39:20+0000");
  script_tag(name:"last_modification", value:"2025-09-15 05:39:20 +0000 (Mon, 15 Sep 2025)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-09-10 15:27:04 +0000 (Tue, 10 Sep 2024)");

  script_name("SUSE: Security Advisory (SUSE-SU-2025:03198-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP6)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:03198-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-202503198-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1228260");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1236589");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1243397");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1243706");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1243933");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1246197");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1249191");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1249348");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1249367");
  script_xref(name:"URL", value:"https://curl.se/ch/");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-updates/2025-September/041687.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'curl' package(s) announced via the SUSE-SU-2025:03198-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for curl fixes the following issues:

Update to version 8.14.1 (jsc#PED-13055, jsc#PED-13056).

Security issues fixed:

- CVE-2025-0665: eventfd double close can cause libcurl to act unreliably (bsc#1236589).
- CVE-2025-4947: QUIC certificate check is skipped with wolfSSL allows for MITM attacks (bsc#1243397).
- CVE-2025-5025: no QUIC certificate pinning with wolfSSL can lead to connections to impostor servers that are not
 easily noticed (bsc#1243706).
- CVE-2025-5399: bug in websocket code can cause libcurl to get trapped in an endless busy-loop when processing
 specially crafted packets (bsc#1243933).
- CVE-2024-6874: punycode conversions to/from IDN can leak stack content when libcurl is built to use the macidn IDN
 backend (bsc#1228260).
- CVE-2025-9086: bug in patch comparison logic when processing cookies can lead to out-of-bounds read in heap buffer
 (bsc#1249191).
- CVE-2025-10148: predictable websocket mask can lead to proxy cache poisoning by malicious server (bsc#1249348).

Other issues fixed:

- Fix wrong return code when --retry is used (bsc#1249367).
 * tool_operate: fix return code when --retry is used but not triggered [b42776b]

- Fix the --ftp-pasv option in curl v8.14.1 (bsc#1246197).
 * tool_getparam: fix --ftp-pasv [5f805ee]

- Fixed with version 8.14.1:
 * TLS: add CURLOPT_SSL_SIGNATURE_ALGORITHMS and --sigalgs.
 * websocket: add option to disable auto-pong reply.
 * huge number of bugfixes.

 Please see [link moved to references] for full changelogs.");

  script_tag(name:"affected", value:"'curl' package(s) on SUSE Linux Enterprise Server 15-SP6.");

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

if(release == "SLES15.0SP6") {

  if(!isnull(res = isrpmvuln(pkg:"curl", rpm:"curl~8.14.1~150600.4.28.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcurl-devel", rpm:"libcurl-devel~8.14.1~150600.4.28.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcurl4-32bit", rpm:"libcurl4-32bit~8.14.1~150600.4.28.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcurl4", rpm:"libcurl4~8.14.1~150600.4.28.1", rls:"SLES15.0SP6"))) {
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
