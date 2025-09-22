# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2025.02739.1");
  script_cve_id("CVE-2025-27221", "CVE-2025-6442");
  script_tag(name:"creation_date", value:"2025-08-11 04:24:53 +0000 (Mon, 11 Aug 2025)");
  script_version("2025-08-19T05:39:49+0000");
  script_tag(name:"last_modification", value:"2025-08-19 05:39:49 +0000 (Tue, 19 Aug 2025)");
  script_tag(name:"cvss_base", value:"5.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:N/I:C/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-08-18 15:49:38 +0000 (Mon, 18 Aug 2025)");

  script_name("SUSE: Security Advisory (SUSE-SU-2025:02739-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP6)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:02739-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-202502739-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1237805");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1245254");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-updates/2025-August/041148.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ruby2.5' package(s) announced via the SUSE-SU-2025:02739-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for ruby2.5 fixes the following issues:

- CVE-2025-6442: Fixed read_header HTTP Request Smuggling Vulnerability in WEBrick (bsc#1245254)
- CVE-2025-27221: Fixed userinfo leakage in URI#join, URI#merge and URI#+ (bsc#1237805)");

  script_tag(name:"affected", value:"'ruby2.5' package(s) on SUSE Linux Enterprise Server 15-SP6.");

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

if(release == "SLES15.0SP6") {

  if(!isnull(res = isrpmvuln(pkg:"libruby2_5-2_5", rpm:"libruby2_5-2_5~2.5.9~150000.4.46.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby2.5", rpm:"ruby2.5~2.5.9~150000.4.46.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby2.5-devel", rpm:"ruby2.5-devel~2.5.9~150000.4.46.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby2.5-devel-extra", rpm:"ruby2.5-devel-extra~2.5.9~150000.4.46.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby2.5-stdlib", rpm:"ruby2.5-stdlib~2.5.9~150000.4.46.1", rls:"SLES15.0SP6"))) {
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
