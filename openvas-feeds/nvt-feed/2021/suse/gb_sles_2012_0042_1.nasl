# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2012.0042.1");
  script_cve_id("CVE-2010-1321", "CVE-2010-1323", "CVE-2011-1526", "CVE-2011-4862");
  script_tag(name:"creation_date", value:"2021-06-09 14:58:29 +0000 (Wed, 09 Jun 2021)");
  script_version("2024-02-02T05:06:07+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:07 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2011-12-26 21:08:00 +0000 (Mon, 26 Dec 2011)");

  script_name("SUSE: Security Advisory (SUSE-SU-2012:0042-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES10\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2012:0042-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2012/suse-su-20120042-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'krb5' package(s) announced via the SUSE-SU-2012:0042-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update of krb5 fixes several security issues.

 * CVE-2011-4862: A remote code execution in the kerberized telnet daemon was fixed. (This only affects the ktelnetd from the krb5-appl RPM, not the regular telnetd supplied by SUSE.)
 * CVE-2011-1526 / MITKRB5-SA-2011-005: Fixed krb5 ftpd unauthorized file access problems.
 * CVE-2010-1323 / MITKRB5-SA-2010-007: Fixed multiple checksum handling vulnerabilities, where: o krb5 clients might have accepted unkeyed SAM-2 challenge checksums o krb5 might have accepted KRB-SAFE checksums with low-entropy derived keys
 * CVE-2010-1321, MITKRB5-SA-2010-005: Fixed GSS-API library null pointer dereference

Security Issue reference:

 * CVE-2011-4862
>");

  script_tag(name:"affected", value:"'krb5' package(s) on SUSE Linux Enterprise Server 10-SP2.");

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

if(release == "SLES10.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"krb5", rpm:"krb5~1.4.3~19.43.37.1", rls:"SLES10.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"krb5-32bit", rpm:"krb5-32bit~1.4.3~19.43.37.1", rls:"SLES10.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"krb5-apps-clients", rpm:"krb5-apps-clients~1.4.3~19.43.37.1", rls:"SLES10.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"krb5-apps-servers", rpm:"krb5-apps-servers~1.4.3~19.43.37.1", rls:"SLES10.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"krb5-client", rpm:"krb5-client~1.4.3~19.43.37.1", rls:"SLES10.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"krb5-devel", rpm:"krb5-devel~1.4.3~19.43.37.1", rls:"SLES10.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"krb5-devel-32bit", rpm:"krb5-devel-32bit~1.4.3~19.43.37.1", rls:"SLES10.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"krb5-server", rpm:"krb5-server~1.4.3~19.43.37.1", rls:"SLES10.0SP2"))) {
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
