# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2017.1441.1");
  script_cve_id("CVE-2017-7484", "CVE-2017-7485", "CVE-2017-7486");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-05-26 18:06:32 +0000 (Fri, 26 May 2017)");

  script_name("SUSE: Security Advisory (SUSE-SU-2017:1441-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2017:1441-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2017/suse-su-20171441-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1029547");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1037603");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1037624");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1038293");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2017-May/002924.html");
  script_xref(name:"URL", value:"https://www.postgresql.org/docs/9.3/static/release-9-3-15.html");
  script_xref(name:"URL", value:"https://www.postgresql.org/docs/9.3/static/release-9-3-16.html");
  script_xref(name:"URL", value:"https://www.postgresql.org/docs/9.3/static/release-9-3-17.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'postgresql93' package(s) announced via the SUSE-SU-2017:1441-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for postgresql93 fixes the following issues:

The PostgreSQL package was updated to 9.3.17, bringing various bug and security fixes.

Bug fixes:

- bsc#1029547: Fix tests with timezone 2017a
- CVE-2017-7486: Restrict visibility of
 pg_user_mappings.umoptions, to protect passwords stored as
 user mapping options. (bsc#1037624)
- CVE-2017-7485: Recognize PGREQUIRESSL variable again. (bsc#1038293)
- CVE-2017-7484: Prevent exposure of statistical information via leaky operators. (bsc#1037603)

More details can be found in the PostgreSQL release announcements:

- [links moved to references]");

  script_tag(name:"affected", value:"'postgresql93' package(s) on SUSE Linux Enterprise Server 12, SUSE Linux Enterprise Server for SAP Applications 12.");

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

if(release == "SLES12.0") {

  if(!isnull(res = isrpmvuln(pkg:"postgresql93", rpm:"postgresql93~9.3.17~24.2", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql93-contrib", rpm:"postgresql93-contrib~9.3.17~24.2", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql93-docs", rpm:"postgresql93-docs~9.3.17~24.2", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql93-server", rpm:"postgresql93-server~9.3.17~24.2", rls:"SLES12.0"))) {
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
