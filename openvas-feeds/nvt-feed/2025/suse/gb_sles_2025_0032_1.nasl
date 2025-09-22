# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2025.0032.1");
  script_cve_id("CVE-2020-36314");
  script_tag(name:"creation_date", value:"2025-01-08 04:18:00 +0000 (Wed, 08 Jan 2025)");
  script_version("2025-01-08T05:38:11+0000");
  script_tag(name:"last_modification", value:"2025-01-08 05:38:11 +0000 (Wed, 08 Jan 2025)");
  script_tag(name:"cvss_base", value:"2.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:N/C:N/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:R/S:U/C:N/I:L/A:L");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-04-13 18:34:05 +0000 (Tue, 13 Apr 2021)");

  script_name("SUSE: Security Advisory (SUSE-SU-2025:0032-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:0032-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-20250032-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'file-roller' package(s) announced via the SUSE-SU-2025:0032-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for file-roller fixes the following issues:

CVE-2020-36314: Fixed directory traversal via directory symlink pointing outside of the target directory (bsc#1189131)");

  script_tag(name:"affected", value:"'file-roller' package(s) on SUSE Linux Enterprise Server 12-SP5.");

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

  if(!isnull(res = isrpmvuln(pkg:"file-roller", rpm:"file-roller~3.20.3~15.9.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"file-roller-debuginfo", rpm:"file-roller-debuginfo~3.20.3~15.9.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"file-roller-debugsource", rpm:"file-roller-debugsource~3.20.3~15.9.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"file-roller-lang", rpm:"file-roller-lang~3.20.3~15.9.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nautilus-file-roller", rpm:"nautilus-file-roller~3.20.3~15.9.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nautilus-file-roller-debuginfo", rpm:"nautilus-file-roller-debuginfo~3.20.3~15.9.1", rls:"SLES12.0SP5"))) {
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
