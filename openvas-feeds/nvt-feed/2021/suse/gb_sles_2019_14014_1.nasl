# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2019.14014.1");
  script_cve_id("CVE-2017-15698", "CVE-2018-8019", "CVE-2018-8020");
  script_tag(name:"creation_date", value:"2021-06-09 14:57:26 +0000 (Wed, 09 Jun 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-10-12 13:22:57 +0000 (Fri, 12 Oct 2018)");

  script_name("SUSE: Security Advisory (SUSE-SU-2019:14014-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2019:14014-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2019/suse-su-201914014-1.html");
  script_xref(name:"URL", value:"http://tomcat.apache.org/native-1.1-doc/miscellaneous/changelog.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1078679");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1103347");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1103348");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2019-April/005314.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libtcnative-1-0' package(s) announced via the SUSE-SU-2019:14014-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for libtcnative-1-0 to version 1.1.34 fixes the following issues:

- CVE-2017-15698: Fixed an improper handling of fields with more than 127 bytes
 which could allow invalid client certificates to be accepted (bsc#1078679).
- CVE-2018-8019: When using an OCSP responder did not correctly handle invalid
 responses. This allowed for revoked client certificates to be incorrectly
 identified. It was therefore possible for users to authenticate with revoked
 certificates when using mutual TLS (bsc#1103348).
- CVE-2018-8020: Did not properly check OCSP pre-produced responses. Revoked
 client certificates may have not been properly identified, allowing for users
 to authenticate with revoked certificates to connections that require mutual
 TLS (bsc#1103347).

For a complete list of changes please see [link moved to references]");

  script_tag(name:"affected", value:"'libtcnative-1-0' package(s) on SUSE Linux Enterprise Server 11-SP4.");

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

if(release == "SLES11.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"libtcnative-1-0", rpm:"libtcnative-1-0~1.3.4~12.5.5.2", rls:"SLES11.0SP4"))) {
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
