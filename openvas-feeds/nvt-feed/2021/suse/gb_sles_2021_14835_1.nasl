# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2021.14835.1");
  script_cve_id("CVE-2021-42780", "CVE-2021-42782");
  script_tag(name:"creation_date", value:"2021-11-02 14:44:50 +0000 (Tue, 02 Nov 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-04-25 16:08:15 +0000 (Mon, 25 Apr 2022)");

  script_name("SUSE: Security Advisory (SUSE-SU-2021:14835-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2021:14835-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2021/suse-su-202114835-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1191957");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1192005");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2021-October/009681.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'opensc' package(s) announced via the SUSE-SU-2021:14835-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for opensc fixes the following issues:

- CVE-2021-42780: Fixed use after return in insert_pin() (bsc#1192005).
- CVE-2021-42782: Stack buffer overflow issues in various places (bsc#1191957).");

  script_tag(name:"affected", value:"'opensc' package(s) on SUSE Linux Enterprise Server 11-SP4.");

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

if(release == "SLES11.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"libopensc2", rpm:"libopensc2~0.11.6~5.27.14.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopensc2-32bit", rpm:"libopensc2-32bit~0.11.6~5.27.14.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"opensc", rpm:"opensc~0.11.6~5.27.14.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"opensc-32bit", rpm:"opensc-32bit~0.11.6~5.27.14.1", rls:"SLES11.0SP4"))) {
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
