# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.18.2.2025.0357.1");
  script_tag(name:"creation_date", value:"2025-02-18 11:01:57 +0000 (Tue, 18 Feb 2025)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("openSUSE Security Advisory (SUSE-SU-2025:0357-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.6");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:0357-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-20250357-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1095184");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1183703");
  script_xref(name:"URL", value:"https://github.com/etcd-io/etcd/blob/v3.5.17/etcd.conf.yml.sample");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2025-February/020281.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'etcd' package(s) announced via the SUSE-SU-2025:0357-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for etcd fixes the following issues:
 Security Update to version 3.5.18:

 * Ensure all goroutines created by StartEtcd to exit before
 closing the errc
 * mvcc: restore tombstone index if it's first revision
 * Bump go toolchain to 1.22.11
 * Avoid deadlock in etcd.Close when stopping during bootstrapping
 * etcdutl/etcdutl: use datadir package to build wal/snapdir
 * Remove duplicated <-s.ReadyNotify()
 * Do not wait for ready notify if the server is stopping
 * Fix mixVersion test case: ensure a snapshot to be sent out
 * *: support custom content check offline in v2store
 * Print warning message for deprecated flags if set
 * fix runtime error: comparing uncomparable type
 * add tls min/max version to grpc proxy

- Fixing a configuration data loss bug:
 Fillup really really wants that the template and the target file
 actually follow the sysconfig format. The current config and the
 current template do not fulfill this requirement.
 Move the current /etc/sysconfig/etcd to /etc/default/etcd and
 install a new sysconfig file which only adds the ETCD_OPTIONS
 option, which is actually used by the unit file.
 This also makes it a bit cleaner to move etcd to use
 --config-file in the long run.

- Update etcd configuration file based on
 [link moved to references]

Update to version 3.5.17:

 * fix(defrag): close temp file in case of error
 * Bump go toolchain to 1.22.9
 * fix(defrag): handle defragdb failure
 * fix(defrag): handle no space left error
 * [3.5] Fix risk of a partial write txn being applied
 * [serverWatchStream] terminate recvLoop on sws.close()

Update to version 3.5.16:

 * Bump go toolchain to 1.22.7
 * Introduce compaction sleep interval flag
 * Fix passing default grpc call options in Kubernetes client
 * Skip leadership check if the etcd instance is active processing
 heartbeats
 * Introduce Kubernetes KV interface to etcd client

Update to version 3.5.15:

 * Differentiate the warning message for rejected client and peer
 * connections
 * Suppress noisy basic auth token deletion log
 * Support multiple values for allowed client and peer TLS
 identities(#18015)
 * print error log when validation on conf change failed

Update to version 3.5.14:

 * etcdutl: Fix snapshot restore memory alloc issue
 * server: Implement WithMmapSize option for backend config
 * gRPC health server sets serving status to NOT_SERVING on defrag
 * server/mvcc: introduce compactBeforeSetFinishedCompact
 failpoint
 * Update the compaction log when bootstrap and update compact's
 signature
 * add experimental-snapshot-catchup-entries flag.
 * Fix retry requests when receiving ErrGPRCNotSupportedForLearner

Update to version 3.5.13:

 * Fix progress notification for watch that doesn't get any events
 * pkg/types: Support Unix sockets in NewURLS
 * added arguments to the grpc-proxy: dial-keepalive-time,
 dial-keepalive-timeout, permit-without-stream
 * server: fix ... [Please see the references for more information on the vulnerabilities]");

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

  if(!isnull(res = isrpmvuln(pkg:"etcd", rpm:"etcd~3.5.18~150000.7.9.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"etcdctl", rpm:"etcdctl~3.5.18~150000.7.9.1", rls:"openSUSELeap15.6"))) {
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
