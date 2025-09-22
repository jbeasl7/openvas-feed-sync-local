# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2015.0258.1");
  script_cve_id("CVE-2014-8137", "CVE-2014-8138", "CVE-2014-8157", "CVE-2014-8158");
  script_tag(name:"creation_date", value:"2021-06-09 14:58:14 +0000 (Wed, 09 Jun 2021)");
  script_version("2025-08-15T15:42:24+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:24 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("SUSE: Security Advisory (SUSE-SU-2015:0258-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2015:0258-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2015/suse-su-20150258-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/909474");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/909475");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/911837");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2015-February/001216.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'jasper' package(s) announced via the SUSE-SU-2015:0258-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for jasper fixes the following security issues:

 *

 CVE-2014-8137: Double free in jas_iccattrval_destroy(). Double call
 to free() allowed attackers to cause a denial of service or possibly
 have unspecified other impact via unknown vectors. (bsc#909474)

 *

 CVE-2014-8138: Heap overflow in jas_decode(). This could be used to
 do an arbitrary write and could result in arbitrary code execution.
 (bsc#909475)

 *

 CVE-2014-8157: Off-by-one error in the jpc_dec_process_sot(). Could
 allow remote attackers to cause a denial of service (crash) or
 possibly execute arbitrary code via a crafted JPEG 2000 image, which
 triggers a heap-based buffer overflow. (bsc#911837)

 *

 CVE-2014-8158: Multiple stack-based buffer overflows in jpc_qmfb.c.
 Could allow remote attackers to cause a denial of service (crash) or
 possibly execute arbitrary code via a crafted JPEG 2000 image.
 (bsc#911837)

Security Issues:

 * CVE-2014-8138
 <[link moved to references]>
 * CVE-2014-8137
 <[link moved to references]>
 * CVE-2014-8157
 <[link moved to references]>
 * CVE-2014-8158
 <[link moved to references]>");

  script_tag(name:"affected", value:"'jasper' package(s) on SUSE Linux Enterprise Desktop 11-SP3, SUSE Linux Enterprise Server 11-SP3, SUSE Linux Enterprise Server for SAP Applications 11-SP3.");

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

if(release == "SLES11.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"libjasper", rpm:"libjasper~1.900.1~134.17.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libjasper-32bit", rpm:"libjasper-32bit~1.900.1~134.17.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libjasper-x86", rpm:"libjasper-x86~1.900.1~134.17.1", rls:"SLES11.0SP3"))) {
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
