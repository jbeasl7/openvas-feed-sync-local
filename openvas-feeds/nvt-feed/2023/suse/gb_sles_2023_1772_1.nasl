# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2023.1772.1");
  script_cve_id("CVE-2023-26767", "CVE-2023-26769");
  script_tag(name:"creation_date", value:"2023-04-05 14:07:33 +0000 (Wed, 05 Apr 2023)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-03-22 02:07:37 +0000 (Wed, 22 Mar 2023)");

  script_name("SUSE: Security Advisory (SUSE-SU-2023:1772-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP1)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:1772-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2023/suse-su-20231772-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1209429");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1209432");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-updates/2023-April/028649.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'liblouis' package(s) announced via the SUSE-SU-2023:1772-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for liblouis fixes the following issues:

- CVE-2023-26767: Fixed buffer overflow vulnerability in lou_logFile function (bsc#1209429).
- CVE-2023-26769: Fixed buffer Overflow vulnerability in resolveSubtable function (bsc#1209432).");

  script_tag(name:"affected", value:"'liblouis' package(s) on SUSE Linux Enterprise Server 15-SP1, SUSE Linux Enterprise Server for SAP Applications 15-SP1.");

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

if(release == "SLES15.0SP1") {

  if(!isnull(res = isrpmvuln(pkg:"liblouis-data", rpm:"liblouis-data~3.3.0~150000.4.13.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"liblouis-devel", rpm:"liblouis-devel~3.3.0~150000.4.13.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"liblouis14", rpm:"liblouis14~3.3.0~150000.4.13.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-louis", rpm:"python3-louis~3.3.0~150000.4.13.1", rls:"SLES15.0SP1"))) {
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
