# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.18.1.2025.0003.1");
  script_cve_id("CVE-2019-11254", "CVE-2020-15106", "CVE-2021-28235", "CVE-2023-47108", "CVE-2023-48795");
  script_tag(name:"creation_date", value:"2025-02-18 11:01:57 +0000 (Tue, 18 Feb 2025)");
  script_version("2025-02-26T05:38:41+0000");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-04-10 18:55:24 +0000 (Mon, 10 Apr 2023)");

  script_name("openSUSE Security Advisory (openSUSE-SU-2025:0003-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.6");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2025:0003-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/PE3D4WEFUCELLDKJUEM2KLPFMME7KTAI/");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1174951");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1181400");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1183703");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1199031");
  script_xref(name:"URL", value:"https://github.com/etcd-io/etcd/compare/v3.4.16...v3.5.0");
  script_xref(name:"URL", value:"https://github.com/etcd-io/etcd/compare/v3.5.2...v3.5.3");
  script_xref(name:"URL", value:"https://github.com/etcd-io/etcd/issues/16740");
  script_xref(name:"URL", value:"https://github.com/etcd-io/etcd/pull/16068#discussion_r1263667496");
  script_xref(name:"URL", value:"https://github.com/golang-jwt/jwt/v4");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'etcd' package(s) announced via the openSUSE-SU-2025:0003-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for etcd fixes the following issues:

Update to version 3.5.12:

 * Bump golang.org/x/crypto to v0.17+ to address CVE-2023-48795
 * test: fix TestHashKVWhenCompacting: ensure all goroutine finished
 * print error log when creating peer listener failed
 * mvcc: Printing etcd backend database related metrics inside scheduleCompaction function
 * dependency: update go version to 1.20.13
 * commit bbolt transaction if there is any pending deleting operations
 * add tests to test tx delete consistency.
 * Don't flock snapshot files
 * Backport adding digest for etcd base image.
 * Add a unit tests and missing flags in etcd help.
 * Add missing flag in etcd help.
 * Backport testutils.ExecuteUntil to 3.5 branch
 * member replace e2e test
 * Check if be is nil to avoid panic when be is overriden with nil by recoverSnapshotBackend on line 517
 * Don't redeclare err and snapshot variable, fixing validation of consistent index and closing database on defer
 * test: enable gofail in release e2e test.
 * [3.5] backport health check e2e tests.
 * tests: Extract e2e cluster setup to separate package

- Update to version 3.5.11:

 * etcdserver: add linearizable_read check to readyz.
 * etcd: Update go version to 1.20.12
 * server: disable redirects in peer communication
 * etcdserver: add metric counters for livez/readyz health checks.
 * etcdserver: add livez and ready http endpoints for etcd.
 * http health check bug fixes
 * server: Split metrics and health code
 * server: Cover V3 health with tests
 * server: Refactor health checks
 * server: Run health check tests in subtests
 * server: Rename test case expect fields
 * server: Use named struct initialization in healthcheck test
 * Backport server: Don't follow redirects when checking peer urls.
 * Backport embed: Add tracing integration test.
 * Backport server: Have tracingExporter own resources it initialises.
 * Backport server: Add sampling rate to distributed tracing.
 * upgrade github.com/stretchr/testify,google.golang.org/genproto/googleapis/api,google.golang.org/grpc to make it consistent
 * CVE-2023-47108: Backport go.opentelemetry.io/otel@v1.20.0 and go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc@v0.46.0
 * github workflow: run arm64 tests on every push
 * etcd: upgrade go version from 1.20.10 to 1.20.11
 * bump bbolt to 1.3.8 for etcd 3.5
 * 3.5: upgrade gRPC-go to 1.58.3
 * Backport corrupt check test fix 'etcd server shouldn't wait for the ready notification infinitely on startup'
 * etcdserver: add cluster id check for hashKVHandler
 * [release-3.5]: upgrade gRPC-go to v1.52.0
 * backport #14125 to release-3.5: Update to grpc-1.47 (and fix the connection-string format)
 * Return to default write scheduler since golang.org/x/net@v0.11.0 started using round robin
 * Bump go to v1.20.10 Part of [link moved to references]
 * bump golang.org/x/net to 0.17.0 Part of [link moved to ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'etcd' package(s) on openSUSE Leap 15.6.");

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

  if(!isnull(res = isrpmvuln(pkg:"etcd", rpm:"etcd~3.5.12~bp156.4.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"etcdctl", rpm:"etcdctl~3.5.12~bp156.4.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"etcdutl", rpm:"etcdutl~3.5.12~bp156.4.3.1", rls:"openSUSELeap15.6"))) {
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
