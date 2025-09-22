# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2021.14729.1");
  script_cve_id("CVE-2014-0191", "CVE-2019-19956", "CVE-2019-20388", "CVE-2020-24977", "CVE-2020-7595", "CVE-2021-3516", "CVE-2021-3517", "CVE-2021-3518", "CVE-2021-3537");
  script_tag(name:"creation_date", value:"2021-06-09 14:56:38 +0000 (Wed, 09 Jun 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-05-25 18:56:11 +0000 (Tue, 25 May 2021)");

  script_name("SUSE: Security Advisory (SUSE-SU-2021:14729-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2021:14729-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2021/suse-su-202114729-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1159928");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1161517");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1161521");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1176179");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1185408");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1185409");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1185410");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1185698");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2021-May/008797.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libxml2' package(s) announced via the SUSE-SU-2021:14729-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for libxml2 fixes the following issues:

Security issues fixed:

- CVE-2021-3537: NULL pointer dereference in valid.c:xmlValidBuildAContentModel (bsc#1185698)
- CVE-2021-3518: Fixed a use after free in xinclude.c:xmlXIncludeDoProcess (bsc#1185408).
- CVE-2021-3517: Fixed a heap based buffer overflow in entities.c:xmlEncodeEntitiesInternal (bsc#1185410).
- CVE-2021-3516: Fixed a use after free in xmlEncodeEntitiesInternal() in entities.c (bsc#1185409)
- CVE-2020-24977: Fixed a global-buffer-overflow in xmlEncodeEntitiesInternal (bsc#1176179).
- CVE-2019-20388: Fixed a memory leak in xmlSchemaPreRun (bsc#1161521).
- CVE-2020-7595: Fixed an infinite loop in an EOF situation (bsc#1161517).
- CVE-2019-19956: Fixed a memory leak in xmlParseBalancedChunkMemoryRecover (bsc#1159928).");

  script_tag(name:"affected", value:"'libxml2' package(s) on SUSE Linux Enterprise Server 11-SP4.");

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

  if(!isnull(res = isrpmvuln(pkg:"libxml2", rpm:"libxml2~2.7.6~0.77.36.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxml2-32bit", rpm:"libxml2-32bit~2.7.6~0.77.36.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxml2-doc", rpm:"libxml2-doc~2.7.6~0.77.36.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxml2-python", rpm:"libxml2-python~2.7.6~0.77.36.1", rls:"SLES11.0SP4"))) {
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
