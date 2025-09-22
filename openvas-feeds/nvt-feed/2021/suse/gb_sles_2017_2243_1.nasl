# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2017.2243.1");
  script_cve_id("CVE-2017-10978", "CVE-2017-10983", "CVE-2017-10984", "CVE-2017-10985", "CVE-2017-10987", "CVE-2017-10988");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-07-19 16:27:01 +0000 (Wed, 19 Jul 2017)");

  script_name("SUSE: Security Advisory (SUSE-SU-2017:2243-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2017:2243-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2017/suse-su-20172243-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1049086");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2017-August/003153.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'freeradius-server' package(s) announced via the SUSE-SU-2017:2243-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for freeradius fixes the following issues:

Security issues fixed:
- CVE-2017-10988: Decode 'signed' attributes correctly. (bnc#1049086)
- CVE-2017-10987: Check for option overflowing the packet. (bnc#1049086)
- CVE-2017-10985: Fix infinite loop and memory exhaustion with 'concat' attributes. (bnc#1049086)
- CVE-2017-10984: Fix write overflow in data2vp_wimax(). (bnc#1049086)
- CVE-2017-10983: Fix read overflow when decoding option 63. (bnc#1049086)
- CVE-2017-10978: Fix read / write overflow in make_secret(). (bnc#1049086)");

  script_tag(name:"affected", value:"'freeradius-server' package(s) on SUSE Linux Enterprise Server 12-SP2, SUSE Linux Enterprise Server for Raspberry Pi 12-SP2, SUSE Linux Enterprise Server for SAP Applications 12-SP2.");

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

  if(!isnull(res = isrpmvuln(pkg:"freeradius-server", rpm:"freeradius-server~3.0.3~17.9.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeradius-server-doc", rpm:"freeradius-server-doc~3.0.3~17.9.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeradius-server-krb5", rpm:"freeradius-server-krb5~3.0.3~17.9.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeradius-server-ldap", rpm:"freeradius-server-ldap~3.0.3~17.9.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeradius-server-libs", rpm:"freeradius-server-libs~3.0.3~17.9.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeradius-server-mysql", rpm:"freeradius-server-mysql~3.0.3~17.9.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeradius-server-perl", rpm:"freeradius-server-perl~3.0.3~17.9.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeradius-server-postgresql", rpm:"freeradius-server-postgresql~3.0.3~17.9.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeradius-server-python", rpm:"freeradius-server-python~3.0.3~17.9.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeradius-server-sqlite", rpm:"freeradius-server-sqlite~3.0.3~17.9.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeradius-server-utils", rpm:"freeradius-server-utils~3.0.3~17.9.1", rls:"SLES12.0SP2"))) {
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
