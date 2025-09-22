# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.883138");
  script_version("2025-01-21T05:37:33+0000");
  script_cve_id("CVE-2019-14824");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-01-21 05:37:33 +0000 (Tue, 21 Jan 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-12-04 18:15:00 +0000 (Fri, 04 Dec 2020)");
  script_tag(name:"creation_date", value:"2019-12-04 03:01:22 +0000 (Wed, 04 Dec 2019)");
  script_name("CentOS Update for 389-ds-base CESA-2019:3981 centos7");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS7");

  script_xref(name:"CESA", value:"2019:3981");
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2019-December/023528.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the '389-ds-base'
  package(s) announced via the CESA-2019:3981 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"389 Directory Server is an LDAP version 3 (LDAPv3) compliant server. The
base packages include the Lightweight Directory Access Protocol (LDAP)
server and command-line utilities for server administration.

Security Fix(es):

  * 389-ds-base: Read permission check bypass via the deref plugin
(CVE-2019-14824)

For more details about the security issue(s), including the impact, a CVSS
score, acknowledgments, and other related information, refer to the CVE
page(s) listed in the References section.

Bug Fix(es):

  * DB Deadlock on modrdn appears to corrupt database and entry cache
(BZ#1749289)

  * After audit log file is rotated, DS version string is logged after each
update (BZ#1754831)

  * Extremely slow LDIF import with ldif2db (BZ#1763622)

  * ns-slapd crash on concurrent SASL BINDs,
connection_call_io_layer_callbacks must hold hold c_mutex (BZ#1763627)

  * CleanAllRUV task limit not enforced (BZ#1767622)");

  script_tag(name:"affected", value:"'389-ds-base' package(s) on CentOS 7.");

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

if(release == "CentOS7") {

  if(!isnull(res = isrpmvuln(pkg:"389-ds-base", rpm:"389-ds-base~1.3.9.1~12.el7_7", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"389-ds-base-devel", rpm:"389-ds-base-devel~1.3.9.1~12.el7_7", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"389-ds-base-libs", rpm:"389-ds-base-libs~1.3.9.1~12.el7_7", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"389-ds-base-snmp", rpm:"389-ds-base-snmp~1.3.9.1~12.el7_7", rls:"CentOS7"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if (__pkg_match) {
    exit(99);
  }
  exit(0);
}

exit(0);
