# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2026.20627.1");
  script_cve_id("CVE-2026-24515", "CVE-2026-25210");
  script_tag(name:"creation_date", value:"2026-03-09 04:38:35 +0000 (Mon, 09 Mar 2026)");
  script_version("2026-03-12T05:56:11+0000");
  script_tag(name:"last_modification", value:"2026-03-12 05:56:11 +0000 (Thu, 12 Mar 2026)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2026-03-10 18:17:12 +0000 (Tue, 10 Mar 2026)");

  script_name("SUSE: Security Advisory (SUSE-SU-2026:20627-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES16\.0\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2026:20627-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2026/suse-su-202620627-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1257144");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1257496");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2026-March/024647.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'expat' package(s) announced via the SUSE-SU-2026:20627-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for expat fixes the following issues:

- CVE-2026-24515: failure to copy the encoding handler data passed to XML_SetUnknownEncodingHandler may cause a NULL
 dereference (bsc#1257144).
- CVE-2026-25210: lack of buffer size check can lead to an integer overflow (bsc#1257496).");

  script_tag(name:"affected", value:"'expat' package(s) on SUSE Linux Enterprise Server 16.0, SUSE Linux Enterprise Server for SAP Applications 16.0.");

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

if(release == "SLES16.0.0") {

  if(!isnull(res = isrpmvuln(pkg:"expat", rpm:"expat~2.7.1~160000.4.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libexpat-devel", rpm:"libexpat-devel~2.7.1~160000.4.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libexpat1", rpm:"libexpat1~2.7.1~160000.4.1", rls:"SLES16.0.0"))) {
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
