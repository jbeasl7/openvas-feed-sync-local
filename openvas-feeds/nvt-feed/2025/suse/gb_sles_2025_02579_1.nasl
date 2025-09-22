# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2025.02579.1");
  script_cve_id("CVE-2025-32023", "CVE-2025-48367");
  script_tag(name:"creation_date", value:"2025-08-04 04:31:53 +0000 (Mon, 04 Aug 2025)");
  script_version("2025-09-08T05:38:50+0000");
  script_tag(name:"last_modification", value:"2025-09-08 05:38:50 +0000 (Mon, 08 Sep 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-09-05 15:16:30 +0000 (Fri, 05 Sep 2025)");

  script_name("SUSE: Security Advisory (SUSE-SU-2025:02579-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:02579-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-202502579-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1244795");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1246058");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1246059");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-updates/2025-July/040981.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'redis' package(s) announced via the SUSE-SU-2025:02579-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for redis fixes the following issues:

- CVE-2025-32023: Fixed out-of-bounds write when working with HyperLogLog commands can lead to remote code execution. (bsc#1246059)
- CVE-2025-48367: Fixed unauthenticated connection causing repeated IP protocol erros can lead to client starvation and DoS. (bsc#1246058)");

  script_tag(name:"affected", value:"'redis' package(s) on SUSE Linux Enterprise Server 15-SP3, SUSE Linux Enterprise Server for SAP Applications 15-SP3.");

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

  if(!isnull(res = isrpmvuln(pkg:"redis", rpm:"redis~6.0.14~150200.6.40.1", rls:"SLES15.0SP3"))) {
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
