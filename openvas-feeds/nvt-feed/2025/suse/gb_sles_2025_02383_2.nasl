# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2025.02383.2");
  script_cve_id("CVE-2025-22872");
  script_tag(name:"creation_date", value:"2025-08-18 04:22:46 +0000 (Mon, 18 Aug 2025)");
  script_version("2025-08-18T05:42:33+0000");
  script_tag(name:"last_modification", value:"2025-08-18 05:42:33 +0000 (Mon, 18 Aug 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("SUSE: Security Advisory (SUSE-SU-2025:02383-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP4|SLES15\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:02383-2");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-202502383-2.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229008");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1241865");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1245087");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-updates/2025-August/041216.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kubernetes1.26' package(s) announced via the SUSE-SU-2025:02383-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for kubernetes1.26 fixes the following issues:

- CVE-2025-22872: Properly handle trailing solidus in unquoted attribute value in foreign content (bsc#1241865).");

  script_tag(name:"affected", value:"'kubernetes1.26' package(s) on SUSE Linux Enterprise Server 15-SP4, SUSE Linux Enterprise Server 15-SP5, SUSE Linux Enterprise Server for SAP Applications 15-SP4, SUSE Linux Enterprise Server for SAP Applications 15-SP5.");

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

  if(!isnull(res = isrpmvuln(pkg:"kubernetes1.26-client", rpm:"kubernetes1.26-client~1.26.15~150400.9.22.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kubernetes1.26-client-common", rpm:"kubernetes1.26-client-common~1.26.15~150400.9.22.1", rls:"SLES15.0SP4"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"kubernetes1.26-client", rpm:"kubernetes1.26-client~1.26.15~150400.9.22.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kubernetes1.26-client-common", rpm:"kubernetes1.26-client-common~1.26.15~150400.9.22.1", rls:"SLES15.0SP5"))) {
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
