# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2023.3755.1");
  script_cve_id("CVE-2021-32490", "CVE-2021-46310", "CVE-2021-46312");
  script_tag(name:"creation_date", value:"2023-09-26 04:21:51 +0000 (Tue, 26 Sep 2023)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-06-28 20:36:35 +0000 (Mon, 28 Jun 2021)");

  script_name("SUSE: Security Advisory (SUSE-SU-2023:3755-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:3755-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2023/suse-su-20233755-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1185895");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1214670");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1214672");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2023-September/016318.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'djvulibre' package(s) announced via the SUSE-SU-2023:3755-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for djvulibre fixes the following issues:

- CVE-2021-46310: Fixed divide by zero in IW44Image.cpp (bsc#1214670).
- CVE-2021-46312: Fixed divide by zero in IW44EncodeCodec.cpp (bsc#1214672).
- CVE-2021-32490: Fixed out of bounds write in function DJVU:filter_bv() via crafted djvu file (bsc#1185895).");

  script_tag(name:"affected", value:"'djvulibre' package(s) on SUSE Linux Enterprise Server 12-SP5, SUSE Linux Enterprise Server for SAP Applications 12-SP5.");

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

if(release == "SLES12.0SP5") {

  if(!isnull(res = isrpmvuln(pkg:"libdjvulibre21", rpm:"libdjvulibre21~3.5.25.3~5.22.1", rls:"SLES12.0SP5"))) {
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
