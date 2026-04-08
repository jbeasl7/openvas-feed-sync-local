# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2026.20936.1");
  script_cve_id("CVE-2026-27622");
  script_tag(name:"creation_date", value:"2026-04-03 04:47:54 +0000 (Fri, 03 Apr 2026)");
  script_version("2026-04-07T07:51:48+0000");
  script_tag(name:"last_modification", value:"2026-04-07 07:51:48 +0000 (Tue, 07 Apr 2026)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2026-03-05 21:07:05 +0000 (Thu, 05 Mar 2026)");

  script_name("SUSE: Security Advisory (SUSE-SU-2026:20936-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES16\.0\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2026:20936-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2026/suse-su-202620936-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1259177");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-updates/2026-April/045216.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openexr' package(s) announced via the SUSE-SU-2026:20936-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for openexr fixes the following issue:

- CVE-2026-27622: crafted multipart deep EXR can cause an heap out-of-bound write (bsc#1259177).");

  script_tag(name:"affected", value:"'openexr' package(s) on SUSE Linux Enterprise Server 16.0, SUSE Linux Enterprise Server for SAP Applications 16.0.");

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

if(release == "SLES16.0.0") {

  if(!isnull(res = isrpmvuln(pkg:"libIex-3_2-31", rpm:"libIex-3_2-31~3.2.2~160000.5.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libIex-3_2-31-x86-64-v3", rpm:"libIex-3_2-31-x86-64-v3~3.2.2~160000.5.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libIlmThread-3_2-31", rpm:"libIlmThread-3_2-31~3.2.2~160000.5.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libIlmThread-3_2-31-x86-64-v3", rpm:"libIlmThread-3_2-31-x86-64-v3~3.2.2~160000.5.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libOpenEXR-3_2-31", rpm:"libOpenEXR-3_2-31~3.2.2~160000.5.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libOpenEXR-3_2-31-x86-64-v3", rpm:"libOpenEXR-3_2-31-x86-64-v3~3.2.2~160000.5.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libOpenEXRCore-3_2-31", rpm:"libOpenEXRCore-3_2-31~3.2.2~160000.5.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libOpenEXRCore-3_2-31-x86-64-v3", rpm:"libOpenEXRCore-3_2-31-x86-64-v3~3.2.2~160000.5.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libOpenEXRUtil-3_2-31", rpm:"libOpenEXRUtil-3_2-31~3.2.2~160000.5.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libOpenEXRUtil-3_2-31-x86-64-v3", rpm:"libOpenEXRUtil-3_2-31-x86-64-v3~3.2.2~160000.5.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openexr", rpm:"openexr~3.2.2~160000.5.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openexr-doc", rpm:"openexr-doc~3.2.2~160000.5.1", rls:"SLES16.0.0"))) {
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
