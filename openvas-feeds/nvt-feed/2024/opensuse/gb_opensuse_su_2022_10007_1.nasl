# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833665");
  script_version("2025-03-11T05:38:16+0000");
  script_cve_id("CVE-2022-297182", "CVE-2022-29718");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_tag(name:"last_modification", value:"2025-03-11 05:38:16 +0000 (Tue, 11 Mar 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-06-12 02:37:04 +0000 (Sun, 12 Jun 2022)");
  script_tag(name:"creation_date", value:"2024-03-04 07:55:10 +0000 (Mon, 04 Mar 2024)");
  script_name("openSUSE: Security Advisory for caddy (openSUSE-SU-2022:10007-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSEBackportsSLE-15-SP4");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2022:10007-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/ID6TRFNJC4CQHO4WTAHUQ4FGQUP3OZ7D");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'caddy'
  package(s) announced via the openSUSE-SU-2022:10007-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for caddy fixes the following issues:
  Update to version 2.5.1:

  * Fixed regression in Unix socket admin endpoints.

  * Fixed regression in caddy trust commands.

  * Hash-based load balancing policies (ip_hash, uri_hash, header, and
       cookie) use an improved highest-random-weight (HRW) algorithm for
       increased consistency.

  * Dynamic upstreams, which is the ability to get the list of upstreams at
       every request (more specifically, every iteration in the proxy loop of
       every request) rather than just once at config-load time.

  * Caddy will automatically try to get relevant certificates from the local
       Tailscale instance.

  * New OpenTelemetry integration.

  * Added new endpoints /pki/ca/ id  and /pki/ca/ id /certificates for
       getting information about Caddy's managed CAs.

  * Rename _caddy to zsh-completion

  * Fix MatchPath sanitizing [bsc#1200279, CVE-2022-29718]");

  script_tag(name:"affected", value:"'caddy' package(s) on openSUSE Backports SLE-15-SP4.");

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

if(release == "openSUSEBackportsSLE-15-SP4") {

  if(!isnull(res = isrpmvuln(pkg:"caddy", rpm:"caddy~2.5.1~bp154.2.5.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"caddy", rpm:"caddy~2.5.1~bp154.2.5.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
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