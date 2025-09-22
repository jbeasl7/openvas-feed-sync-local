# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.122099");
  script_cve_id("CVE-2011-1678", "CVE-2011-2522", "CVE-2011-2694", "CVE-2011-2724", "CVE-2011-3585");
  script_tag(name:"creation_date", value:"2015-10-06 11:13:03 +0000 (Tue, 06 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-01-10 17:53:00 +0000 (Fri, 10 Jan 2020)");

  script_name("Oracle: Security Advisory (ELSA-2011-1221)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux6");

  script_xref(name:"Advisory-ID", value:"ELSA-2011-1221");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2011-1221.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'cifs-utils, samba' package(s) announced via the ELSA-2011-1221 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"cifs-utils:

[4.8.1-2.2]
- fix handling of check_newline return code in mount.cifs (bz 725508)

[4.8.1-2.1]
- mount.cifs: handle ENOSPC/EFBIG condition when altering mtab (bz 725508)

samba:

[3.5.6-86.4]
- Fix cleartext authentication after applying Windows security patch KB2536276
- resolves: #728517

[3.5.6-86.3]
- Security Release, fixes CVE-2011-2694, CVE-2011-2522
- resolves: #722560

[3.5.6-86.2]
- Fix cups location publishing
- resolves: #716374

[3.5.6-86.1]
- Fix joining principal
- resolves: #717563");

  script_tag(name:"affected", value:"'cifs-utils, samba' package(s) on Oracle Linux 6.");

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

  if(!isnull(res = isrpmvuln(pkg:"cifs-utils", rpm:"cifs-utils~4.8.1~2.el6_1.2", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsmbclient", rpm:"libsmbclient~3.5.6~86.el6_1.4", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsmbclient-devel", rpm:"libsmbclient-devel~3.5.6~86.el6_1.4", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba", rpm:"samba~3.5.6~86.el6_1.4", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-client", rpm:"samba-client~3.5.6~86.el6_1.4", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-common", rpm:"samba-common~3.5.6~86.el6_1.4", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-doc", rpm:"samba-doc~3.5.6~86.el6_1.4", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-domainjoin-gui", rpm:"samba-domainjoin-gui~3.5.6~86.el6_1.4", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-swat", rpm:"samba-swat~3.5.6~86.el6_1.4", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-winbind", rpm:"samba-winbind~3.5.6~86.el6_1.4", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-winbind-clients", rpm:"samba-winbind-clients~3.5.6~86.el6_1.4", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-winbind-devel", rpm:"samba-winbind-devel~3.5.6~86.el6_1.4", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-winbind-krb5-locator", rpm:"samba-winbind-krb5-locator~3.5.6~86.el6_1.4", rls:"OracleLinux6"))) {
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
