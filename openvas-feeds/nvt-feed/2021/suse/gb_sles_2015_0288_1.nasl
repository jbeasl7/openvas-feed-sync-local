# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2015.0288.1");
  script_cve_id("CVE-2014-8157", "CVE-2014-8158");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:24+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:24 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("SUSE: Security Advisory (SUSE-SU-2015:0288-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2015:0288-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2015/suse-su-20150288-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/911837");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2015-February/001223.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'jasper' package(s) announced via the SUSE-SU-2015:0288-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"jasper was updated to fix two security issues.

These security issues were fixed:
- CVE-2014-8157: Off-by-one error in the jpc_dec_process_sot function in JasPer 1.900.1 and earlier allowed remote attackers to cause a denial of service (crash) or possibly execute arbitrary code via a crafted JPEG 2000 image, which triggers a heap-based buffer overflow (bnc#911837).
CVE-2014-8158: Multiple stack-based buffer overflows in jpc_qmfb.c in JasPer 1.900.1 and earlier allowed remote attackers to cause a denial of service (crash) or possibly execute arbitrary code via a crafted JPEG 2000 image (bnc#911837).");

  script_tag(name:"affected", value:"'jasper' package(s) on SUSE Linux Enterprise Desktop 12, SUSE Linux Enterprise Server 12, SUSE Linux Enterprise Server for SAP Applications 12.");

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

  if(!isnull(res = isrpmvuln(pkg:"libjasper1", rpm:"libjasper1~1.900.1~170.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libjasper1-32bit", rpm:"libjasper1-32bit~1.900.1~170.1", rls:"SLES12.0"))) {
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
