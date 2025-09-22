# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2025.02314.1");
  script_cve_id("CVE-2025-49794", "CVE-2025-49795", "CVE-2025-49796", "CVE-2025-6021", "CVE-2025-6170");
  script_tag(name:"creation_date", value:"2025-07-17 04:22:04 +0000 (Thu, 17 Jul 2025)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"9.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-06-16 16:15:19 +0000 (Mon, 16 Jun 2025)");

  script_name("SUSE: Security Advisory (SUSE-SU-2025:02314-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP5|SLES15\.0SP6)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:02314-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-202502314-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1244554");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1244555");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1244557");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1244590");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1244700");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2025-July/021818.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libxml2' package(s) announced via the SUSE-SU-2025:02314-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for libxml2 fixes the following issues:

- CVE-2025-49794: Fixed a heap use after free which could lead to denial of service. (bsc#1244554)
- CVE-2025-49796: Fixed type confusion which could lead to denial of service. (bsc#1244557)
- CVE-2025-49795: Fixed a null pointer dereference which could lead to denial of service. (bsc#1244555)
- CVE-2025-6170: Fixed a stack buffer overflow which could lead to a crash. (bsc#1244700)
- CVE-2025-6021: Fixed an integer overflow in xmlBuildQName() which could lead to stack buffer overflow. (bsc#1244590)");

  script_tag(name:"affected", value:"'libxml2' package(s) on SUSE Linux Enterprise Server 15-SP5, SUSE Linux Enterprise Server 15-SP6, SUSE Linux Enterprise Server for SAP Applications 15-SP5.");

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

  if(!isnull(res = isrpmvuln(pkg:"libxml2-2", rpm:"libxml2-2~2.10.3~150500.5.29.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxml2-2-32bit", rpm:"libxml2-2-32bit~2.10.3~150500.5.29.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxml2-devel", rpm:"libxml2-devel~2.10.3~150500.5.29.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxml2-tools", rpm:"libxml2-tools~2.10.3~150500.5.29.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-libxml2", rpm:"python3-libxml2~2.10.3~150500.5.29.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-libxml2", rpm:"python311-libxml2~2.10.3~150500.5.29.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES15.0SP6") {

  if(!isnull(res = isrpmvuln(pkg:"libxml2-2", rpm:"libxml2-2~2.10.3~150500.5.29.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxml2-2-32bit", rpm:"libxml2-2-32bit~2.10.3~150500.5.29.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxml2-devel", rpm:"libxml2-devel~2.10.3~150500.5.29.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxml2-tools", rpm:"libxml2-tools~2.10.3~150500.5.29.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-libxml2", rpm:"python3-libxml2~2.10.3~150500.5.29.1", rls:"SLES15.0SP6"))) {
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
