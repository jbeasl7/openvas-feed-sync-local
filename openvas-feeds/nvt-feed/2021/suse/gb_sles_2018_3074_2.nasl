# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2018.3074.2");
  script_tag(name:"creation_date", value:"2021-06-09 14:57:35 +0000 (Wed, 09 Jun 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("SUSE: Security Advisory (SUSE-SU-2018:3074-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2018:3074-2");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2018/suse-su-20183074-2.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1108308");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2018-October/004711.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'postgresql10' package(s) announced via the SUSE-SU-2018:3074-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for brings postgresql10 version 10.5 to SUSE Linux Enterprise 12 SP3. (FATE#325659 bnc#1108308)

This release marks the change of the versioning scheme for PostgreSQL to a 'x.y' format. This means the next minor releases of PostgreSQL will be 10.1, 10.2, ... and the next major release will be 11.

* Logical Replication

Logical replication extends the current replication features of PostgreSQL with the ability to send modifications on a per-database and per-table level to different PostgreSQL databases. Users can now fine-tune the data replicated to various database clusters and will have the ability to perform zero-downtime upgrades to future major PostgreSQL versions.

* Declarative Table Partitioning

Table partitioning has existed for years in PostgreSQL but required a user to maintain a nontrivial set of rules and triggers for the partitioning to work. PostgreSQL 10 introduces a table partitioning syntax that lets users easily create and maintain range and list partitioned tables.

* Improved Query Parallelism

PostgreSQL 10 provides better support for parallelized queries by allowing more parts of the query execution process to be parallelized. Improvements include additional types of data scans that are parallelized as well as optimizations when the data is recombined,
such as pre-sorting. These enhancements allow results to be returned more quickly.

* Quorum Commit for Synchronous Replication

PostgreSQL 10 introduces quorum commit for synchronous replication,
which allows for flexibility in how a primary database receives acknowledgement that changes were successfully written to remote replicas.");

  script_tag(name:"affected", value:"'postgresql10' package(s) on SUSE Linux Enterprise Server 12-SP2.");

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

if(release == "SLES12.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"libecpg6", rpm:"libecpg6~10.5~1.3.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpq5", rpm:"libpq5~10.5~1.3.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpq5-32bit", rpm:"libpq5-32bit~10.5~1.3.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql-init", rpm:"postgresql-init~10~17.20.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql10", rpm:"postgresql10~10.5~1.3.2", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql10-contrib", rpm:"postgresql10-contrib~10.5~1.3.2", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql10-docs", rpm:"postgresql10-docs~10.5~1.3.2", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql10-server", rpm:"postgresql10-server~10.5~1.3.2", rls:"SLES12.0SP2"))) {
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
