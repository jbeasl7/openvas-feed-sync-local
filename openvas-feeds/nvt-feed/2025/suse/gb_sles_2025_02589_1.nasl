# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2025.02589.1");
  script_cve_id("CVE-2025-32988", "CVE-2025-32989", "CVE-2025-32990", "CVE-2025-6395");
  script_tag(name:"creation_date", value:"2025-08-04 04:31:53 +0000 (Mon, 04 Aug 2025)");
  script_version("2025-08-18T05:42:33+0000");
  script_tag(name:"last_modification", value:"2025-08-18 05:42:33 +0000 (Mon, 18 Aug 2025)");
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-08-15 19:32:53 +0000 (Fri, 15 Aug 2025)");

  script_name("SUSE: Security Advisory (SUSE-SU-2025:02589-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP4|SLES15\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:02589-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-202502589-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1246232");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1246233");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1246267");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1246299");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-updates/2025-August/041003.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'gnutls' package(s) announced via the SUSE-SU-2025:02589-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for gnutls fixes the following issues:

- CVE-2025-6395: Fix NULL pointer dereference when 2nd Client Hello omits PSK (bsc#1246299)
- CVE-2025-32988: Fix double-free due to incorrect ownership handling in the export logic of SAN entries containing an otherName (bsc#1246232)
- CVE-2025-32989: Fix heap buffer overread when handling the CT SCT extension during X.509 certificate parsing (bsc#1246233)
- CVE-2025-32990: Fix 1-byte heap buffer overflow when parsing templates with certtool (bsc#1246267)");

  script_tag(name:"affected", value:"'gnutls' package(s) on SUSE Linux Enterprise Server 15-SP4, SUSE Linux Enterprise Server 15-SP5, SUSE Linux Enterprise Server for SAP Applications 15-SP4, SUSE Linux Enterprise Server for SAP Applications 15-SP5.");

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

  if(!isnull(res = isrpmvuln(pkg:"gnutls", rpm:"gnutls~3.7.3~150400.4.50.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgnutls-devel", rpm:"libgnutls-devel~3.7.3~150400.4.50.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgnutls30", rpm:"libgnutls30~3.7.3~150400.4.50.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgnutls30-32bit", rpm:"libgnutls30-32bit~3.7.3~150400.4.50.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgnutls30-hmac", rpm:"libgnutls30-hmac~3.7.3~150400.4.50.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgnutls30-hmac-32bit", rpm:"libgnutls30-hmac-32bit~3.7.3~150400.4.50.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgnutlsxx-devel", rpm:"libgnutlsxx-devel~3.7.3~150400.4.50.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgnutlsxx28", rpm:"libgnutlsxx28~3.7.3~150400.4.50.1", rls:"SLES15.0SP4"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"gnutls", rpm:"gnutls~3.7.3~150400.4.50.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gnutls-guile", rpm:"gnutls-guile~3.7.3~150400.4.50.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgnutls-devel", rpm:"libgnutls-devel~3.7.3~150400.4.50.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgnutls30", rpm:"libgnutls30~3.7.3~150400.4.50.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgnutls30-32bit", rpm:"libgnutls30-32bit~3.7.3~150400.4.50.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgnutls30-hmac", rpm:"libgnutls30-hmac~3.7.3~150400.4.50.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgnutls30-hmac-32bit", rpm:"libgnutls30-hmac-32bit~3.7.3~150400.4.50.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgnutlsxx-devel", rpm:"libgnutlsxx-devel~3.7.3~150400.4.50.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgnutlsxx28", rpm:"libgnutlsxx28~3.7.3~150400.4.50.1", rls:"SLES15.0SP5"))) {
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
