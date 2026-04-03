# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2026.1159.1");
  script_cve_id("CVE-2026-32776", "CVE-2026-32777", "CVE-2026-32778");
  script_tag(name:"creation_date", value:"2026-04-01 08:03:57 +0000 (Wed, 01 Apr 2026)");
  script_version("2026-04-02T06:06:11+0000");
  script_tag(name:"last_modification", value:"2026-04-02 06:06:11 +0000 (Thu, 02 Apr 2026)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2026-03-17 15:52:53 +0000 (Tue, 17 Mar 2026)");

  script_name("SUSE: Security Advisory (SUSE-SU-2026:1159-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2026:1159-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2026/suse-su-20261159-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1259711");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1259726");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1259729");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-updates/2026-March/045203.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'expat' package(s) announced via the SUSE-SU-2026:1159-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for expat fixes the following issues:

- CVE-2026-32776: NULL pointer dereference when processing empty external parameter entities inside an entity
 declaration value (bsc#1259726).
- CVE-2026-32777: denial of service due to infinite loop in DTD content parsing (bsc#1259711).
- CVE-2026-32778: NULL pointer dereference in `setContext` on retry after an out-of-memory condition (bsc#1259729).");

  script_tag(name:"affected", value:"'expat' package(s) on SUSE Linux Enterprise Server 12-SP5.");

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

  if(!isnull(res = isrpmvuln(pkg:"expat", rpm:"expat~2.7.1~21.52.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libexpat-devel", rpm:"libexpat-devel~2.7.1~21.52.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libexpat1", rpm:"libexpat1~2.7.1~21.52.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libexpat1-32bit", rpm:"libexpat1-32bit~2.7.1~21.52.1", rls:"SLES12.0SP5"))) {
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
