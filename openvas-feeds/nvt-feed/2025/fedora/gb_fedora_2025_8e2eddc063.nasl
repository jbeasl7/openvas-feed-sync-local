# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2025.8101210110010099063");
  script_cve_id("CVE-2025-27151", "CVE-2025-32023", "CVE-2025-48367");
  script_tag(name:"creation_date", value:"2025-07-25 04:17:17 +0000 (Fri, 25 Jul 2025)");
  script_version("2025-08-22T05:39:46+0000");
  script_tag(name:"last_modification", value:"2025-08-22 05:39:46 +0000 (Fri, 22 Aug 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-08-21 22:28:57 +0000 (Thu, 21 Aug 2025)");

  script_name("Fedora: Security Advisory (FEDORA-2025-8e2eddc063)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC42");

  script_xref(name:"Advisory-ID", value:"FEDORA-2025-8e2eddc063");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2025-8e2eddc063");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2380113");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2380116");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2380118");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'valkey' package(s) announced via the FEDORA-2025-8e2eddc063 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"**Valkey 8.0.4** - Released Mon 07 July 2025

Upgrade urgency SECURITY: This release includes security fixes we recommend you
apply as soon as possible.

Security fixes

* **CVE-2025-32023** prevent out-of-bounds write during hyperloglog operations (#2146)
* **CVE-2025-48367** retry accept on transient errors (#2315)

Security fixes backported from 8.1.2

* **CVE-2025-27151** Check length of AOF file name in valkey-check-aof (#2146)");

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

  if(!isnull(res = isrpmvuln(pkg:"valkey", rpm:"valkey~8.0.4~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"valkey-compat-redis", rpm:"valkey-compat-redis~8.0.4~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"valkey-compat-redis-devel", rpm:"valkey-compat-redis-devel~8.0.4~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"valkey-debuginfo", rpm:"valkey-debuginfo~8.0.4~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"valkey-debugsource", rpm:"valkey-debugsource~8.0.4~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"valkey-devel", rpm:"valkey-devel~8.0.4~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"valkey-doc", rpm:"valkey-doc~8.0.4~1.fc42", rls:"FC42"))) {
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
