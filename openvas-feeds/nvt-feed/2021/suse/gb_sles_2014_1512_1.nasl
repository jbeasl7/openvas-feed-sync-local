# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2014.1512.1");
  script_cve_id("CVE-2014-3566", "CVE-2014-3567", "CVE-2014-3568");
  script_tag(name:"creation_date", value:"2021-06-09 14:58:15 +0000 (Wed, 09 Jun 2021)");
  script_version("2024-02-02T14:37:48+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:48 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2014-10-23 15:33:41 +0000 (Thu, 23 Oct 2014)");

  script_name("SUSE: Security Advisory (SUSE-SU-2014:1512-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2014:1512-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2014/suse-su-20141512-1/");
  script_xref(name:"URL", value:"https://www.suse.com/support/kb/doc.php?id=7015773");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'compat-openssl098' package(s) announced via the SUSE-SU-2014:1512-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"compat-openssl098 was updated to fix three security issues.

NOTE: this update alone DOESN'T FIX the POODLE SSL protocol vulnerability.
OpenSSL only adds downgrade detection support for client applications. See [link moved to references] for mitigations.

These security issues were fixed:
- Session ticket memory leak (CVE-2014-3567).
- Fixed build option no-ssl3 (CVE-2014-3568).
- Added support for TLS_FALLBACK_SCSV (CVE-2014-3566).");

  script_tag(name:"affected", value:"'compat-openssl098' package(s) on SUSE Linux Enterprise Desktop 12, SUSE Linux Enterprise Module for Legacy Software 12.");

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

  if(!isnull(res = isrpmvuln(pkg:"compat-openssl098-debugsource", rpm:"compat-openssl098-debugsource~0.9.8j~62.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenssl0_9_8", rpm:"libopenssl0_9_8~0.9.8j~62.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenssl0_9_8-debuginfo", rpm:"libopenssl0_9_8-debuginfo~0.9.8j~62.1", rls:"SLES12.0"))) {
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
