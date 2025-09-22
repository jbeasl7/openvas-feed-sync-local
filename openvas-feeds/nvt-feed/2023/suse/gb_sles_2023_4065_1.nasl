# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2023.4065.1");
  script_cve_id("CVE-2021-42782", "CVE-2023-40661");
  script_tag(name:"creation_date", value:"2023-10-13 04:22:05 +0000 (Fri, 13 Oct 2023)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:P/AC:L/PR:L/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-11-14 17:11:38 +0000 (Tue, 14 Nov 2023)");

  script_name("SUSE: Security Advisory (SUSE-SU-2023:4065-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:4065-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2023/suse-su-20234065-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1191957");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1215761");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2023-October/016643.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'opensc' package(s) announced via the SUSE-SU-2023:4065-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for opensc fixes the following issues:

- CVE-2021-42782: Fixed several stack buffer overflows (bsc#1191957).
- CVE-2023-40661: Fixed several memory safety issues that could happen
 during the card enrollment process using pkcs15-init (bsc#1215761).");

  script_tag(name:"affected", value:"'opensc' package(s) on SUSE Linux Enterprise Server 12-SP5, SUSE Linux Enterprise Server for SAP Applications 12-SP5.");

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

  if(!isnull(res = isrpmvuln(pkg:"opensc", rpm:"opensc~0.13.0~3.25.1", rls:"SLES12.0SP5"))) {
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
