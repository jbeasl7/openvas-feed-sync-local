# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.123519");
  script_cve_id("CVE-2013-4485");
  script_tag(name:"creation_date", value:"2015-10-06 11:04:58 +0000 (Tue, 06 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:P");

  script_name("Oracle: Security Advisory (ELSA-2013-1752)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux6");

  script_xref(name:"Advisory-ID", value:"ELSA-2013-1752");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2013-1752.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the '389-ds-base' package(s) announced via the ELSA-2013-1752 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[1.2.11.15-30]
- Resolves: bug 1024977 CVE-2013-4485 389-ds-base: DoS due to improper handling of ger attr searches

[1.2.11.15-29]
- Bump version to 1.2.11.15-29
- Resolves: bug 1008013: DS91: ns-slapd stuck in DS_Sleep

[1.2.11.15-28]
- Bump version to 1.2.11.15-28
- Resolves: Bug 1016038 - Users from AD sub OU does not sync to IPA (ticket 47488)

[1.2.11.15-27]
- Bump version to 1.2.11.15-27
- Resolves: Bug 1013735 - CLEANALLRUV doesn't run across all replicas (ticket 47509)

[1.2.11.15-26]
- Bump version to 1.2.11.15-26
- Resolves: Bug 947583 - ldapdelete returns non-leaf entry error while trying to remove a leaf entry (ticket 47534)

[1.2.11.15-25]
- Bump version to 1.2.11.15-25
- Resolves: Bug 1006846 - 2Master replication with SASL/GSSAPI auth broken (ticket 47523)
- Resolves: Bug 1007452 - Under specific values of nsDS5ReplicaName, replication may get broken or updates (ticket 47489)

[1.2.11.15-24]
- Bump version to 1.2.11.15-24
- Resolves: Bug 982325 - Overflow in nsslapd-disk-monitoring-threshold, Changed CONFIG_INT to CONFIG_LONG for nsslapd-disk-monioring-threshold (ticket 47427)

[1.2.11.15-23]
- Bump version to 1.2.11.15-23
- Resolves: Bug 1000632 - CVE-2013-4283 389-ds-base: ns-slapd crash due to bogus DN
- Resolves: Bug 1002260 - server fails to start after upgrade(schema error) (ticket 47318)");

  script_tag(name:"affected", value:"'389-ds-base' package(s) on Oracle Linux 6.");

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

if(release == "OracleLinux6") {

  if(!isnull(res = isrpmvuln(pkg:"389-ds-base", rpm:"389-ds-base~1.2.11.15~30.el6_5", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"389-ds-base-devel", rpm:"389-ds-base-devel~1.2.11.15~30.el6_5", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"389-ds-base-libs", rpm:"389-ds-base-libs~1.2.11.15~30.el6_5", rls:"OracleLinux6"))) {
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
