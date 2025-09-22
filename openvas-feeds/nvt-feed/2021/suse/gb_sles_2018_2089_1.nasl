# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2018.2089.1");
  script_cve_id("CVE-2018-0495");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"1.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-08-10 16:42:12 +0000 (Fri, 10 Aug 2018)");

  script_name("SUSE: Security Advisory (SUSE-SU-2018:2089-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2018:2089-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2018/suse-su-20182089-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1064455");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1090766");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1097410");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2018-July/004331.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libgcrypt' package(s) announced via the SUSE-SU-2018:2089-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for libgcrypt fixes the following issues:

The following security vulnerability was addressed:

- CVE-2018-0495: Mitigate a novel side-channel attack by enabling blinding for
 ECDSA signatures (bsc#1097410).

The following other issues were fixed:

- Extended the fipsdrv dsa-sign and dsa-verify commands with the
 --algo parameter for the FIPS testing of DSA SigVer and SigGen (bsc#1064455).
- Ensure libgcrypt20-hmac and libgcrypt20 are installed in the correct order. (bsc#1090766)");

  script_tag(name:"affected", value:"'libgcrypt' package(s) on SUSE Linux Enterprise Desktop 12-SP3, SUSE Linux Enterprise Server 12-SP3, SUSE Linux Enterprise Server for SAP Applications 12-SP3.");

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

  if(!isnull(res = isrpmvuln(pkg:"libgcrypt20", rpm:"libgcrypt20~1.6.1~16.55.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgcrypt20-32bit", rpm:"libgcrypt20-32bit~1.6.1~16.55.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgcrypt20-hmac", rpm:"libgcrypt20-hmac~1.6.1~16.55.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgcrypt20-hmac-32bit", rpm:"libgcrypt20-hmac-32bit~1.6.1~16.55.1", rls:"SLES12.0SP3"))) {
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
