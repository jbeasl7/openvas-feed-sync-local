# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2025.2999999110241011009");
  script_cve_id("CVE-2025-21605");
  script_tag(name:"creation_date", value:"2025-05-26 07:22:06 +0000 (Mon, 26 May 2025)");
  script_version("2025-05-27T05:40:43+0000");
  script_tag(name:"last_modification", value:"2025-05-27 05:40:43 +0000 (Tue, 27 May 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Fedora: Security Advisory (FEDORA-2025-2ccc1f4ed9)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC42");

  script_xref(name:"Advisory-ID", value:"FEDORA-2025-2ccc1f4ed9");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2025-2ccc1f4ed9");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'valkey' package(s) announced via the FEDORA-2025-2ccc1f4ed9 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"**Valkey 8.0.3** - Released Wed 23 Apr 2025

Upgrade urgency SECURITY: This release includes security fixes we recommend you
apply as soon as possible.

Bug fixes

* Optimize RDB load performance and fix cluster mode resizing on replica side (#1199)
* Fix memory leak in forgotten node ping ext code path (#1574)
* Fix cluster info sent stats for message with light header (#1563)
* Fix module LatencyAddSample still work when latency-monitor-threshold is 0 (#1541)
* Fix potential crash in radix tree recompression of huge keys (#1722)
* Fix error 'SSL routines::bad length' when connTLSWrite is called second time with smaller buffer (#1737)
* Fix temp file leak druing replication error handling (#1721)
* Fix ACL LOAD crash on replica since the primary client don't has a user (#1842)
* Fix RANDOMKEY infinite loop during CLIENT PAUSE (#1850)
* fix: add samples to stream object consumer trees (#1825)
* Fix cluster slot stats assertion during promotion of replica (#1950)
* Fix panic in primary when blocking shutdown after previous block with timeout (#1948)
* Ignore stale gossip packets that arrive out of order (#1777)
* Fix incorrect lag reported in XINFO GROUPS (#1952)
* Avoid shard id update of replica if not matching with primary shard id (#573)

Security fixes

* **CVE-2025-21605** Limit output buffer for unauthenticated clients (#1993)");

  script_tag(name:"affected", value:"'valkey' package(s) on Fedora 42.");

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

if(release == "FC42") {

  if(!isnull(res = isrpmvuln(pkg:"valkey", rpm:"valkey~8.0.3~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"valkey-compat-redis", rpm:"valkey-compat-redis~8.0.3~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"valkey-compat-redis-devel", rpm:"valkey-compat-redis-devel~8.0.3~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"valkey-debuginfo", rpm:"valkey-debuginfo~8.0.3~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"valkey-debugsource", rpm:"valkey-debugsource~8.0.3~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"valkey-devel", rpm:"valkey-devel~8.0.3~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"valkey-doc", rpm:"valkey-doc~8.0.3~1.fc42", rls:"FC42"))) {
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
