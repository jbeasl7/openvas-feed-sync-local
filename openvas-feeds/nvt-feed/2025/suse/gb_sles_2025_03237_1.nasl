# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2025.03237.1");
  script_cve_id("CVE-2023-6350", "CVE-2023-6351", "CVE-2025-48174", "CVE-2025-48175");
  script_tag(name:"creation_date", value:"2025-09-18 04:08:17 +0000 (Thu, 18 Sep 2025)");
  script_version("2025-09-18T05:38:39+0000");
  script_tag(name:"last_modification", value:"2025-09-18 05:38:39 +0000 (Thu, 18 Sep 2025)");
  script_tag(name:"cvss_base", value:"9.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-06-04 20:02:37 +0000 (Wed, 04 Jun 2025)");

  script_name("SUSE: Security Advisory (SUSE-SU-2025:03237-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP4|SLES15\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:03237-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-202503237-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1217614");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1217615");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1243269");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1243270");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-updates/2025-September/041718.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libavif' package(s) announced via the SUSE-SU-2025:03237-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for libavif fixes the following issues:


Update to 1.3.0:

- CVE-2025-48175: Fixed an integer overflows in multiplications involving rgbRowBytes, yRowBytes, uRowBytes, and vRowBytes. (bsc#1243270)
- CVE-2025-48174: Fixed an integer overflow and resultant buffer overflow in stream->offset+size. (bsc#1243269)
- CVE-2023-6350: Fixed an out of bounds memory to alphaItemIndices. (bsc#1217614)
- CVE-2023-6351: Fixed a use-after-free in colorProperties. (bsc#1217615)");

  script_tag(name:"affected", value:"'libavif' package(s) on SUSE Linux Enterprise Server 15-SP4, SUSE Linux Enterprise Server 15-SP5, SUSE Linux Enterprise Server for SAP Applications 15-SP4, SUSE Linux Enterprise Server for SAP Applications 15-SP5.");

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

if(release == "SLES15.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"libavif16", rpm:"libavif16~1.3.0~150400.3.6.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES15.0SP5") {

  if(!isnull(res = isrpmvuln(pkg:"libavif16", rpm:"libavif16~1.3.0~150400.3.6.1", rls:"SLES15.0SP5"))) {
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
