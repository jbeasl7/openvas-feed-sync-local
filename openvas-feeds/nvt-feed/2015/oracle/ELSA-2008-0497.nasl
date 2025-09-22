# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.122574");
  script_cve_id("CVE-2008-1951");
  script_tag(name:"creation_date", value:"2015-10-08 11:48:26 +0000 (Thu, 08 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Oracle: Security Advisory (ELSA-2008-0497)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=(OracleLinux4|OracleLinux5)");

  script_xref(name:"Advisory-ID", value:"ELSA-2008-0497");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2008-0497.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'sblim' package(s) announced via the ELSA-2008-0497 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[1.31.0.1.el5_2.1]
- Add oracle-enterprise-release.patch

[1.31.el5_2.1]
- Remove RPATH from shared libraries in sblim-cmpi-{dns,fsvol,network,
 nfsv3,nfsv4,samba,syslog}
 and create appropriate record in /etc/ld.so.conf.d (CVE-2008-1951)
 Resolves: #446859");

  script_tag(name:"affected", value:"'sblim' package(s) on Oracle Linux 4, Oracle Linux 5.");

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

if(release == "OracleLinux4") {

  if(!isnull(res = isrpmvuln(pkg:"sblim", rpm:"sblim~1~13a.0.1.el4_6.1", rls:"OracleLinux4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sblim-cmpi-base", rpm:"sblim-cmpi-base~1.5.4~13a.0.1.el4_6.1", rls:"OracleLinux4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sblim-cmpi-base-devel", rpm:"sblim-cmpi-base-devel~1.5.4~13a.0.1.el4_6.1", rls:"OracleLinux4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sblim-cmpi-base-test", rpm:"sblim-cmpi-base-test~1.5.4~13a.0.1.el4_6.1", rls:"OracleLinux4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sblim-cmpi-devel", rpm:"sblim-cmpi-devel~1.0.4~13a.0.1.el4_6.1", rls:"OracleLinux4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sblim-cmpi-fsvol", rpm:"sblim-cmpi-fsvol~1.4.3~13a.0.1.el4_6.1", rls:"OracleLinux4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sblim-cmpi-fsvol-devel", rpm:"sblim-cmpi-fsvol-devel~1.4.3~13a.0.1.el4_6.1", rls:"OracleLinux4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sblim-cmpi-fsvol-test", rpm:"sblim-cmpi-fsvol-test~1.4.3~13a.0.1.el4_6.1", rls:"OracleLinux4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sblim-cmpi-network", rpm:"sblim-cmpi-network~1.3.7~13a.0.1.el4_6.1", rls:"OracleLinux4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sblim-cmpi-network-devel", rpm:"sblim-cmpi-network-devel~1.3.7~13a.0.1.el4_6.1", rls:"OracleLinux4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sblim-cmpi-network-test", rpm:"sblim-cmpi-network-test~1.3.7~13a.0.1.el4_6.1", rls:"OracleLinux4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sblim-cmpi-nfsv3", rpm:"sblim-cmpi-nfsv3~1.0.13~13a.0.1.el4_6.1", rls:"OracleLinux4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sblim-cmpi-nfsv3-test", rpm:"sblim-cmpi-nfsv3-test~1.0.13~13a.0.1.el4_6.1", rls:"OracleLinux4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sblim-cmpi-nfsv4", rpm:"sblim-cmpi-nfsv4~1.0.11~13a.0.1.el4_6.1", rls:"OracleLinux4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sblim-cmpi-nfsv4-test", rpm:"sblim-cmpi-nfsv4-test~1.0.11~13a.0.1.el4_6.1", rls:"OracleLinux4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sblim-cmpi-params", rpm:"sblim-cmpi-params~1.2.4~13a.0.1.el4_6.1", rls:"OracleLinux4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sblim-cmpi-params-test", rpm:"sblim-cmpi-params-test~1.2.4~13a.0.1.el4_6.1", rls:"OracleLinux4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sblim-cmpi-sysfs", rpm:"sblim-cmpi-sysfs~1.1.8~13a.0.1.el4_6.1", rls:"OracleLinux4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sblim-cmpi-sysfs-test", rpm:"sblim-cmpi-sysfs-test~1.1.8~13a.0.1.el4_6.1", rls:"OracleLinux4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sblim-cmpi-syslog", rpm:"sblim-cmpi-syslog~0.7.9~13a.0.1.el4_6.1", rls:"OracleLinux4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sblim-cmpi-syslog-test", rpm:"sblim-cmpi-syslog-test~0.7.9~13a.0.1.el4_6.1", rls:"OracleLinux4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sblim-gather", rpm:"sblim-gather~2.1.1~13a.0.1.el4_6.1", rls:"OracleLinux4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sblim-gather-devel", rpm:"sblim-gather-devel~2.1.1~13a.0.1.el4_6.1", rls:"OracleLinux4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sblim-gather-provider", rpm:"sblim-gather-provider~2.1.1~13a.0.1.el4_6.1", rls:"OracleLinux4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sblim-gather-test", rpm:"sblim-gather-test~2.1.1~13a.0.1.el4_6.1", rls:"OracleLinux4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sblim-testsuite", rpm:"sblim-testsuite~1.2.4~13a.0.1.el4_6.1", rls:"OracleLinux4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sblim-wbemcli", rpm:"sblim-wbemcli~1.5.1~13a.0.1.el4_6.1", rls:"OracleLinux4"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "OracleLinux5") {

  if(!isnull(res = isrpmvuln(pkg:"sblim", rpm:"sblim~1~31.0.1.el5_2.1", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sblim-cim-client", rpm:"sblim-cim-client~1.3.3~31.0.1.el5_2.1", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sblim-cim-client-javadoc", rpm:"sblim-cim-client-javadoc~1~31.0.1.el5_2.1", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sblim-cim-client-manual", rpm:"sblim-cim-client-manual~1~31.0.1.el5_2.1", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sblim-cmpi-base", rpm:"sblim-cmpi-base~1.5.5~31.0.1.el5_2.1", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sblim-cmpi-base-devel", rpm:"sblim-cmpi-base-devel~1.5.5~31.0.1.el5_2.1", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sblim-cmpi-base-test", rpm:"sblim-cmpi-base-test~1.5.5~31.0.1.el5_2.1", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sblim-cmpi-devel", rpm:"sblim-cmpi-devel~1.0.4~31.0.1.el5_2.1", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sblim-cmpi-dns", rpm:"sblim-cmpi-dns~0.5.2~31.0.1.el5_2.1", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sblim-cmpi-dns-devel", rpm:"sblim-cmpi-dns-devel~1~31.0.1.el5_2.1", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sblim-cmpi-dns-test", rpm:"sblim-cmpi-dns-test~1~31.0.1.el5_2.1", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sblim-cmpi-fsvol", rpm:"sblim-cmpi-fsvol~1.4.4~31.0.1.el5_2.1", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sblim-cmpi-fsvol-devel", rpm:"sblim-cmpi-fsvol-devel~1.4.4~31.0.1.el5_2.1", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sblim-cmpi-fsvol-test", rpm:"sblim-cmpi-fsvol-test~1.4.4~31.0.1.el5_2.1", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sblim-cmpi-network", rpm:"sblim-cmpi-network~1.3.8~31.0.1.el5_2.1", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sblim-cmpi-network-devel", rpm:"sblim-cmpi-network-devel~1.3.8~31.0.1.el5_2.1", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sblim-cmpi-network-test", rpm:"sblim-cmpi-network-test~1.3.8~31.0.1.el5_2.1", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sblim-cmpi-nfsv3", rpm:"sblim-cmpi-nfsv3~1.0.14~31.0.1.el5_2.1", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sblim-cmpi-nfsv3-test", rpm:"sblim-cmpi-nfsv3-test~1.0.14~31.0.1.el5_2.1", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sblim-cmpi-nfsv4", rpm:"sblim-cmpi-nfsv4~1.0.12~31.0.1.el5_2.1", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sblim-cmpi-nfsv4-test", rpm:"sblim-cmpi-nfsv4-test~1.0.12~31.0.1.el5_2.1", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sblim-cmpi-params", rpm:"sblim-cmpi-params~1.2.6~31.0.1.el5_2.1", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sblim-cmpi-params-test", rpm:"sblim-cmpi-params-test~1.2.6~31.0.1.el5_2.1", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sblim-cmpi-samba", rpm:"sblim-cmpi-samba~0.5.2~31.0.1.el5_2.1", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sblim-cmpi-samba-devel", rpm:"sblim-cmpi-samba-devel~1~31.0.1.el5_2.1", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sblim-cmpi-samba-test", rpm:"sblim-cmpi-samba-test~1~31.0.1.el5_2.1", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sblim-cmpi-sysfs", rpm:"sblim-cmpi-sysfs~1.1.9~31.0.1.el5_2.1", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sblim-cmpi-sysfs-test", rpm:"sblim-cmpi-sysfs-test~1.1.9~31.0.1.el5_2.1", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sblim-cmpi-syslog", rpm:"sblim-cmpi-syslog~0.7.11~31.0.1.el5_2.1", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sblim-cmpi-syslog-test", rpm:"sblim-cmpi-syslog-test~0.7.11~31.0.1.el5_2.1", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sblim-gather", rpm:"sblim-gather~2.1.2~31.0.1.el5_2.1", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sblim-gather-devel", rpm:"sblim-gather-devel~2.1.2~31.0.1.el5_2.1", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sblim-gather-provider", rpm:"sblim-gather-provider~2.1.2~31.0.1.el5_2.1", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sblim-gather-test", rpm:"sblim-gather-test~2.1.2~31.0.1.el5_2.1", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sblim-testsuite", rpm:"sblim-testsuite~1.2.4~31.0.1.el5_2.1", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sblim-tools-libra", rpm:"sblim-tools-libra~0.2.3~31.0.1.el5_2.1", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sblim-tools-libra-devel", rpm:"sblim-tools-libra-devel~0.2.3~31.0.1.el5_2.1", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sblim-wbemcli", rpm:"sblim-wbemcli~1.5.1~31.0.1.el5_2.1", rls:"OracleLinux5"))) {
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
