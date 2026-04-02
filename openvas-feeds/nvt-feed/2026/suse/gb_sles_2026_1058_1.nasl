# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2026.1058.1");
  script_cve_id("CVE-2020-13934", "CVE-2020-13935", "CVE-2020-13943", "CVE-2020-17527", "CVE-2021-24122", "CVE-2021-25122", "CVE-2021-25329", "CVE-2021-30640", "CVE-2021-33037", "CVE-2021-41079", "CVE-2021-43980", "CVE-2022-23181", "CVE-2022-42252", "CVE-2023-24998", "CVE-2023-28708", "CVE-2023-28709", "CVE-2023-41080", "CVE-2023-42795", "CVE-2023-44487", "CVE-2023-45468", "CVE-2023-46589", "CVE-2024-21733", "CVE-2024-23672", "CVE-2024-24549", "CVE-2024-34750", "CVE-2024-38286", "CVE-2024-50379", "CVE-2024-52316", "CVE-2024-54677", "CVE-2025-24813", "CVE-2025-31651", "CVE-2025-46701", "CVE-2025-48988", "CVE-2025-48989", "CVE-2025-49125", "CVE-2025-52434", "CVE-2025-52520", "CVE-2025-53506", "CVE-2025-55752", "CVE-2025-55754", "CVE-2025-61795", "CVE-2025-66614", "CVE-2026-24733");
  script_tag(name:"creation_date", value:"2026-03-30 04:58:33 +0000 (Mon, 30 Mar 2026)");
  script_version("2026-03-30T06:15:36+0000");
  script_tag(name:"last_modification", value:"2026-03-30 06:15:36 +0000 (Mon, 30 Mar 2026)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-05-05 20:14:47 +0000 (Mon, 05 May 2025)");

  script_name("SUSE: Security Advisory (SUSE-SU-2026:1058-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2026:1058-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2026/suse-su-20261058-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1216182");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1243895");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1246318");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1246389");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1258371");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1258385");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1259224");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2026-March/024949.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'tomcat' package(s) announced via the SUSE-SU-2026:1058-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for tomcat fixes the following issues:

Update to Tomcat 9.0.115:

- CVE-2025-48989: HTTP/2 protocol (including DNS over HTTPS) is vulnerable to 'MadeYouReset' DoS attack (bsc#1243895).
- CVE-2025-52434: race condition on connection close when using the APR/Native connector could lead to a JVM crash
 (bsc#1246389).
- CVE-2025-53506: uncontrolled resource HTTP/2 client consumption vulnerability (bsc#1246318).
- CVE-2025-66614: client certificate verification bypass due to virtual host mapping (bsc#1258371).
- CVE-2026-24733: improper input validation on HTTP/0.9 requests (bsc#1258385).
- CVE-2023-44487: Rapid reset attack (bsc#1216182).");

  script_tag(name:"affected", value:"'tomcat' package(s) on SUSE Linux Enterprise Server 12-SP5.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");

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

  if(!isnull(res = isrpmvuln(pkg:"tomcat", rpm:"tomcat~9.0.115~3.160.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat-admin-webapps", rpm:"tomcat-admin-webapps~9.0.115~3.160.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat-docs-webapp", rpm:"tomcat-docs-webapp~9.0.115~3.160.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat-el-3_0-api", rpm:"tomcat-el-3_0-api~9.0.115~3.160.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat-javadoc", rpm:"tomcat-javadoc~9.0.115~3.160.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat-jsp-2_3-api", rpm:"tomcat-jsp-2_3-api~9.0.115~3.160.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat-lib", rpm:"tomcat-lib~9.0.115~3.160.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat-servlet-4_0-api", rpm:"tomcat-servlet-4_0-api~9.0.115~3.160.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat-webapps", rpm:"tomcat-webapps~9.0.115~3.160.1", rls:"SLES12.0SP5"))) {
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
