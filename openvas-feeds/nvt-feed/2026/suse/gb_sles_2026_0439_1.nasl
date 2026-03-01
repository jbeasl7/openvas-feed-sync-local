# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2026.0439.1");
  script_cve_id("CVE-2024-45310", "CVE-2025-22869", "CVE-2025-22870", "CVE-2025-22872", "CVE-2025-27144", "CVE-2025-47913", "CVE-2025-47914", "CVE-2025-58181", "CVE-2025-65105", "CVE-2025-8556");
  script_tag(name:"creation_date", value:"2026-02-13 04:41:11 +0000 (Fri, 13 Feb 2026)");
  script_version("2026-02-13T05:57:48+0000");
  script_tag(name:"last_modification", value:"2026-02-13 05:57:48 +0000 (Fri, 13 Feb 2026)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-12-05 19:08:58 +0000 (Fri, 05 Dec 2025)");

  script_name("SUSE: Security Advisory (SUSE-SU-2026:0439-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP6)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2026:0439-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2026/suse-su-20260439-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1237608");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1238611");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1239322");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1241710");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1253506");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1253784");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1253967");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255462");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1257432");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2026-February/024109.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'apptainer' package(s) announced via the SUSE-SU-2026:0439-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"- CVE-2024-45310: Fixed runc being tricked into creating empty
 files/directories on host (bsc#1257432)
- CVE-2025-65105: Fixed security bypass due to disabling security
 options (bsc#1255462)
- CVE-2025-47914: Fixed malformed constraint may cause denial of
 service in golang.org/x/crypto/ssh/agent (bsc#1253967)
- CVE-2025-58181: Fixed unbounded memory consumption in
 golang.org/x/crypto/ssh (bsc#1253784)
- CVE-2025-47913: Fixed potential denial of service in
 golang.org/x/crypto/ssh/agent (bsc#1253506)
- CVE-2025-22872: Fixed incorrect Neutralization of Input During
 Web Page Generation in x/net (bsc#1241710)
- CVE-2025-22870: Fixed HTTP Proxy bypass using IPv6 Zone IDs in
 golang.org/x/net (bsc#1238611)
- CVE-2025-22869: Fixed potential denial of service in
 golang.org/x/crypto (bsc#1239322)
- CVE-2025-27144: Fixed DoS in go-jose Parsing in
 github.com/go-jose/go-jose (bsc#1237608)
- CVE-2025-8556: Fixed missing and wrong validation can lead
 to incorrect results in github.com/cloudflare/circl

Other fixes:

- Update to 1.4.5");

  script_tag(name:"affected", value:"'apptainer' package(s) on SUSE Linux Enterprise Server 15-SP6.");

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

  if(!isnull(res = isrpmvuln(pkg:"apptainer", rpm:"apptainer~1.4.5~150600.4.12.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apptainer-sle15_6", rpm:"apptainer-sle15_6~1.4.5~150600.4.12.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsquashfuse0", rpm:"libsquashfuse0~0.5.0~150600.3.2.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"squashfuse", rpm:"squashfuse~0.5.0~150600.3.2.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"squashfuse-tools", rpm:"squashfuse-tools~0.5.0~150600.3.2.1", rls:"SLES15.0SP6"))) {
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
