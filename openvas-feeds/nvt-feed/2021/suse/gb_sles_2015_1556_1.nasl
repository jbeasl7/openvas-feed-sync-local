# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2015.1556.1");
  script_cve_id("CVE-2015-5621");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:24+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:24 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("SUSE: Security Advisory (SUSE-SU-2015:1556-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2015:1556-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2015/suse-su-20151556-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/909479");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/935863");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/935876");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/940084");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/940188");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2015-September/001593.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'net-snmp' package(s) announced via the SUSE-SU-2015:1556-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The following issues have been fixed within this update:

* fix btrfs output inside HOST-RESOURCES-MIB::hrStorageDescr.
 (bsc#909479)
* fix an incompletely initialized vulnerability within the
 snmp_pdu_parse() function of snmp_api.c. (bsc#940188, CVE-2015-5621)
* add build requirement 'procps' to fix a net-snmp-config error
 (bsc#935863)
* --disable-md5 to allow operation in FIPS mode and not use the
 old algorithm (bsc#935876 bsc#940084)
* also stop snmptrapd on removal");

  script_tag(name:"affected", value:"'net-snmp' package(s) on SUSE Linux Enterprise Desktop 12, SUSE Linux Enterprise Server 12, SUSE Linux Enterprise Server for SAP Applications 12.");

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

if(release == "SLES12.0") {

  if(!isnull(res = isrpmvuln(pkg:"libsnmp30-32bit", rpm:"libsnmp30-32bit~5.7.2.1~4.3.2", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsnmp30", rpm:"libsnmp30~5.7.2.1~4.3.2", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"net-snmp", rpm:"net-snmp~5.7.2.1~4.3.2", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-SNMP", rpm:"perl-SNMP~5.7.2.1~4.3.2", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"snmp-mibs", rpm:"snmp-mibs~5.7.2.1~4.3.2", rls:"SLES12.0"))) {
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
