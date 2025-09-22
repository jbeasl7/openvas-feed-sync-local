# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.18.1.2025.0131.1");
  script_cve_id("CVE-2024-51744");
  script_tag(name:"creation_date", value:"2025-04-21 04:06:46 +0000 (Mon, 21 Apr 2025)");
  script_version("2025-05-01T05:40:03+0000");
  script_tag(name:"last_modification", value:"2025-05-01 05:40:03 +0000 (Thu, 01 May 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("openSUSE Security Advisory (openSUSE-SU-2025:0131-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.6");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2025:0131-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/EUVFYQAJREBRWHGVJH4PINWMTHG2NH7G/");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1239294");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1239728");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'coredns' package(s) announced via the openSUSE-SU-2025:0131-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for coredns fixes the following issues:

- Update to version 1.12.1:
 * core: Increase CNAME lookup limit from 7 to 10 (#7153)
 * plugin/kubernetes: Fix handling of pods having DeletionTimestamp set
 * plugin/kubernetes: Revert 'only create PTR records for endpoints with
 hostname defined'
 * plugin/forward: added option failfast_all_unhealthy_upstreams to return
 servfail if all upstreams are down
 * bump dependencies, fixing boo#1239294 and boo#1239728

- Update to version 1.12.0:
 * New multisocket plugin - allows CoreDNS to listen on multiple sockets
 * bump deps

- Update to version 1.11.4:
 * forward plugin: new option next, to try alternate upstreams when receiving
 specified response codes upstreams on (functions like the external plugin
 alternate)
 * dnssec plugin: new option to load keys from AWS Secrets Manager
 * rewrite plugin: new option to revert EDNS0 option rewrites in responses

- Update to version 1.11.3+git129.387f34d:
 * fix CVE-2024-51744 (bsc#1232991)
 build(deps): bump github.com/golang-jwt/jwt/v4 from 4.5.0 to 4.5.1 (#6955)
 * core: set cache-control max-age as integer, not float (#6764)
 * Issue-6671: Fixed the order of plugins. (#6729)
 * `root`: explicit mark `dnssec` support (#6753)
 * feat: dnssec load keys from AWS Secrets Manager (#6618)
 * fuzzing: fix broken oss-fuzz build (#6880)
 * Replace k8s.io/utils/strings/slices by Go stdlib slices (#6863)
 * Update .go-version to 1.23.2 (#6920)
 * plugin/rewrite: Add 'revert' parameter for EDNS0 options (#6893)
 * Added OpenSSF Scorecard Badge (#6738)
 * fix(cwd): Restored backwards compatibility of Current Workdir (#6731)
 * fix: plugin/auto: call OnShutdown() for each zone at its own OnShutdown() (#6705)
 * feature: log queue and buffer memory size configuration (#6591)
 * plugin/bind: add zone for link-local IPv6 instead of skipping (#6547)
 * only create PTR records for endpoints with hostname defined (#6898)
 * fix: reverter should execute the reversion in reversed order (#6872)
 * plugin/etcd: fix etcd connection leakage when reload (#6646)
 * kubernetes: Add useragent (#6484)
 * Update build (#6836)
 * Update grpc library use (#6826)
 * Bump go version from 1.21.11 to 1.21.12 (#6800)
 * Upgrade antonmedv/expr to expr-lang/expr (#6814)
 * hosts: add hostsfile as label for coredns_hosts_entries (#6801)
 * fix TestCorefile1 panic for nil handling (#6802)");

  script_tag(name:"affected", value:"'coredns' package(s) on openSUSE Leap 15.6.");

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

if(release == "openSUSELeap15.6") {

  if(!isnull(res = isrpmvuln(pkg:"coredns", rpm:"coredns~1.12.1~bp156.4.6.5", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"coredns-extras", rpm:"coredns-extras~1.12.1~bp156.4.6.5", rls:"openSUSELeap15.6"))) {
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
