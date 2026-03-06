# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2026.1100051021100152");
  script_cve_id("CVE-2025-67733", "CVE-2026-21863");
  script_tag(name:"creation_date", value:"2026-03-05 04:37:00 +0000 (Thu, 05 Mar 2026)");
  script_version("2026-03-05T05:55:06+0000");
  script_tag(name:"last_modification", value:"2026-03-05 05:55:06 +0000 (Thu, 05 Mar 2026)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:P/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2026-02-25 17:34:02 +0000 (Wed, 25 Feb 2026)");

  script_name("Fedora: Security Advisory (FEDORA-2026-1d05f1d152)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC42");

  script_xref(name:"Advisory-ID", value:"FEDORA-2026-1d05f1d152");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2026-1d05f1d152");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2442220");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2442231");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'valkey' package(s) announced via the FEDORA-2026-1d05f1d152 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"**Valkey 8.0.7** - Released Mon 23 February 2026

Upgrade urgency SECURITY: This release includes security fixes we recommend you
apply as soon as possible.

Security fixes

* (**CVE-2026-21863**) Remote DoS with malformed Valkey Cluster bus message
* (**CVE-2025-67733**) RESP Protocol Injection via Lua error_reply

Bug fixes

* Fix ltrim should not call signalModifiedKey when no elements are removed (#2787)
* Fix chained replica crash when doing dual channel replication (#2983)
* Fix used_memory_dataset underflow due to miscalculated used_memory_overhead (#3005)
* Avoids crash during MODULE UNLOAD when ACL rules reference a module command and subcommand (#3160)
* Fix server assert on ACL LOAD and resetchannels (#3182)
* Fix bug causing no response flush sometimes when IO threads are busy (#3205)");

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

  if(!isnull(res = isrpmvuln(pkg:"valkey", rpm:"valkey~8.0.7~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"valkey-compat-redis", rpm:"valkey-compat-redis~8.0.7~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"valkey-compat-redis-devel", rpm:"valkey-compat-redis-devel~8.0.7~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"valkey-debuginfo", rpm:"valkey-debuginfo~8.0.7~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"valkey-debugsource", rpm:"valkey-debugsource~8.0.7~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"valkey-devel", rpm:"valkey-devel~8.0.7~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"valkey-doc", rpm:"valkey-doc~8.0.7~1.fc42", rls:"FC42"))) {
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
