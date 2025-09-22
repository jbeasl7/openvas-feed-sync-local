# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2017.0639.1");
  script_cve_id("CVE-2014-9913", "CVE-2015-7696", "CVE-2015-7697", "CVE-2016-9844");
  script_tag(name:"creation_date", value:"2021-06-09 14:58:00 +0000 (Wed, 09 Jun 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-01-20 15:32:07 +0000 (Fri, 20 Jan 2017)");

  script_name("SUSE: Security Advisory (SUSE-SU-2017:0639-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2017:0639-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2017/suse-su-20170639-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1013992");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1013993");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/950110");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/950111");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2017-March/002686.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'unzip' package(s) announced via the SUSE-SU-2017:0639-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for unzip fixes the following issues:

- CVE-2014-9913: Specially crafted zip files could trigger invalid memory writes possibly resulting in DoS or corruption (bsc#1013993)
- CVE-2015-7696: Specially crafted zip files with password protection could trigger a crash and lead to denial of service (bsc#950110)
- CVE-2015-7697: Specially crafted zip files could trigger an endless loop and lead to denial of service (bsc#950111)
- CVE-2016-9844: Specially crafted zip files could trigger invalid memory writes possibly resulting in DoS or corruption (bsc#1013992)");

  script_tag(name:"affected", value:"'unzip' package(s) on SUSE Linux Enterprise Server 11-SP4, SUSE Linux Enterprise Server for SAP Applications 11-SP4.");

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

  if(!isnull(res = isrpmvuln(pkg:"unzip", rpm:"unzip~6.00~11.17.1", rls:"SLES11.0SP4"))) {
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
