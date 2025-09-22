# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2025.02039.1");
  script_cve_id("CVE-2025-23165", "CVE-2025-23166", "CVE-2025-23167");
  script_tag(name:"creation_date", value:"2025-06-23 04:17:35 +0000 (Mon, 23 Jun 2025)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("SUSE: Security Advisory (SUSE-SU-2025:02039-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:02039-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-202502039-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1239949");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1243217");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1243218");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1243220");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-updates/2025-June/040407.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'nodejs20' package(s) announced via the SUSE-SU-2025:02039-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for nodejs20 fixes the following issues:

Update to 20.19.2:

- CVE-2025-23166: improper error handling in async cryptographic operations crashes process (bsc#1243218).
- CVE-2025-23167: improper HTTP header block termination in llhttp (bsc#1243220).
- CVE-2025-23165: add missing call to uv_fs_req_cleanup (bsc#1243217).

Other bugfixes:

- Build with PIE (bsc#1239949)");

  script_tag(name:"affected", value:"'nodejs20' package(s) on SUSE Linux Enterprise Server 15-SP5, SUSE Linux Enterprise Server for SAP Applications 15-SP5.");

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

if(release == "SLES15.0SP5") {

  if(!isnull(res = isrpmvuln(pkg:"nodejs20", rpm:"nodejs20~20.19.2~150500.11.21.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs20-devel", rpm:"nodejs20-devel~20.19.2~150500.11.21.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs20-docs", rpm:"nodejs20-docs~20.19.2~150500.11.21.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"npm20", rpm:"npm20~20.19.2~150500.11.21.1", rls:"SLES15.0SP5"))) {
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
