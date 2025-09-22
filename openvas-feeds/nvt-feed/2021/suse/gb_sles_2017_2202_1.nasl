# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2017.2202.1");
  script_cve_id("CVE-2017-10978", "CVE-2017-10983", "CVE-2017-10984", "CVE-2017-10985", "CVE-2017-10986", "CVE-2017-10987", "CVE-2017-10988");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-07-19 16:27:01 +0000 (Wed, 19 Jul 2017)");

  script_name("SUSE: Security Advisory (SUSE-SU-2017:2202-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2017:2202-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2017/suse-su-20172202-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1049086");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2017-August/003144.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'freeradius-server' package(s) announced via the SUSE-SU-2017:2202-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for freeradius-server fixes the following issues:

- update to 3.0.15 (bsc#1049086)
 * Bind the lifetime of program name and python path to the module
 * CVE-2017-10978: FR-GV-201: Check input / output length in make_secret() (bsc#1049086)
 * CVE-2017-10983: FR-GV-206: Fix read overflow when decoding DHCP option 63 (bsc#1049086)
 * CVE-2017-10984: FR-GV-301: Fix write overflow in data2vp_wimax() (bsc#1049086)
 * CVE-2017-10985: FR-GV-302: Fix infinite loop and memory exhaustion with 'concat' attributes (bsc#1049086)
 * CVE-2017-10986: FR-GV-303: Fix infinite read in dhcp_attr2vp() (bsc#1049086)
 * CVE-2017-10987: FR-GV-304: Fix buffer over-read in fr_dhcp_decode_suboptions() (bsc#1049086)
 * CVE-2017-10988: FR-GV-305: Decode 'signed' attributes correctly. (bsc#1049086)
 * FR-AD-001: use strncmp() instead of memcmp() for bounded data
 * Print messages when we see deprecated configuration items
 * Show reasons why we couldn't parse a certificate expiry time
 * Be more accepting about truncated ASN1 times.
 * Fix OpenSSL API issue which could leak small amounts of memory.
 * For Access-Reject, call rad_authlog() after running the
 post-auth section, just like for Access-Accept.
 * Don't crash when reading corrupted data from session resumption
 cache.
 * Parse port in dhcpclient.
 * Don't leak memory for OpenSSL.
 * Portability fixes taken from OpenBSD port collection.
 * run rad_authlog after post-auth for Access-Reject.
 * Don't process VMPS packets twice.
 * Fix attribute truncation in rlm_perl
 * Fix bug when processing huntgroups.
 * FR-AD-002 - Bind the lifetime of program name and python path to the module
 * FR-AD-003 - Pass correct statement length into sqlite3_prepare[_v2]");

  script_tag(name:"affected", value:"'freeradius-server' package(s) on SUSE Linux Enterprise Server 12-SP3, SUSE Linux Enterprise Server for SAP Applications 12-SP3.");

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

if(release == "SLES12.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"freeradius-server", rpm:"freeradius-server~3.0.15~2.3.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeradius-server-doc", rpm:"freeradius-server-doc~3.0.15~2.3.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeradius-server-krb5", rpm:"freeradius-server-krb5~3.0.15~2.3.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeradius-server-ldap", rpm:"freeradius-server-ldap~3.0.15~2.3.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeradius-server-libs", rpm:"freeradius-server-libs~3.0.15~2.3.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeradius-server-mysql", rpm:"freeradius-server-mysql~3.0.15~2.3.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeradius-server-perl", rpm:"freeradius-server-perl~3.0.15~2.3.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeradius-server-postgresql", rpm:"freeradius-server-postgresql~3.0.15~2.3.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeradius-server-python", rpm:"freeradius-server-python~3.0.15~2.3.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeradius-server-sqlite", rpm:"freeradius-server-sqlite~3.0.15~2.3.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeradius-server-utils", rpm:"freeradius-server-utils~3.0.15~2.3.1", rls:"SLES12.0SP3"))) {
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
