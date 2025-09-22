# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2025.02354.1");
  script_cve_id("CVE-2025-5278");
  script_tag(name:"creation_date", value:"2025-07-21 04:23:14 +0000 (Mon, 21 Jul 2025)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"3.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:L");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-05-27 21:15:23 +0000 (Tue, 27 May 2025)");

  script_name("SUSE: Security Advisory (SUSE-SU-2025:02354-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:02354-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-202502354-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1219321");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1221632");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1243767");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-updates/2025-July/040760.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'coreutils' package(s) announced via the SUSE-SU-2025:02354-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"- CVE-2025-5278: Fixed heap buffer under-read may lead to a crash or leak sensitive data (bsc#1243767)

Other fixes:

- ls: avoid triggering automounts (bsc#1221632)
- tail: fix tailing sysfs files where PAGE_SIZE > BUFSIZ (bsc#1219321)");

  script_tag(name:"affected", value:"'coreutils' package(s) on SUSE Linux Enterprise Server 15-SP3, SUSE Linux Enterprise Server for SAP Applications 15-SP3.");

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

if(release == "SLES15.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"coreutils", rpm:"coreutils~8.32~150300.3.11.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"coreutils-doc", rpm:"coreutils-doc~8.32~150300.3.11.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"coreutils-lang", rpm:"coreutils-lang~8.32~150300.3.11.1", rls:"SLES15.0SP3"))) {
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
