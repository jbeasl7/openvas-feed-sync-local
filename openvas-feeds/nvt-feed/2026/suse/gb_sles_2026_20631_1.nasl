# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2026.20631.1");
  script_cve_id("CVE-2025-10911", "CVE-2025-8732", "CVE-2026-0990", "CVE-2026-0992", "CVE-2026-1757");
  script_tag(name:"creation_date", value:"2026-03-09 04:38:35 +0000 (Mon, 09 Mar 2026)");
  script_version("2026-03-10T10:15:11+0000");
  script_tag(name:"last_modification", value:"2026-03-10 10:15:11 +0000 (Tue, 10 Mar 2026)");
  script_tag(name:"cvss_base", value:"1.7");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2026-02-02 13:15:58 +0000 (Mon, 02 Feb 2026)");

  script_name("SUSE: Security Advisory (SUSE-SU-2026:20631-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES16\.0\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2026:20631-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2026/suse-su-202620631-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1247850");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1247858");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1250553");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256804");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256807");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256808");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256809");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256810");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256811");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256812");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1257593");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1257594");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1257595");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2026-March/024645.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libxml2, libxslt' package(s) announced via the SUSE-SU-2026:20631-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for libxml2, libxslt fixes the following issues:

Changes in libxml2:

- CVE-2026-0990: call stack overflow may lead to application crash due to infinite recursion in
 `xmlCatalogXMLResolveURI` (bsc#1256807, bsc#1256811).
- CVE-2026-0992: excessive resource consumption when processing XML catalogs due to exponential behavior when handling
 `nextCatalog` elements (bsc#1256809, bsc#1256812).
- CVE-2025-8732: infinite recursion in catalog parsing functions when processing malformed SGML catalog files
 (bsc#1247858).
- CVE-2026-1757: memory leak in the `xmllint` interactive shell (bsc#1257594, bsc#1257595).
- CVE-2025-10911: parsing xsl nodes may lead to use-after-free with key data stored cross-RVT (bsc#1250553)");

  script_tag(name:"affected", value:"'libxml2, libxslt' package(s) on SUSE Linux Enterprise Server 16.0, SUSE Linux Enterprise Server for SAP Applications 16.0.");

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

  if(!isnull(res = isrpmvuln(pkg:"libexslt0", rpm:"libexslt0~1.1.43~160000.4.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxml2-2", rpm:"libxml2-2~2.13.8~160000.4.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxml2-devel", rpm:"libxml2-devel~2.13.8~160000.4.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxml2-doc", rpm:"libxml2-doc~2.13.8~160000.4.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxml2-tools", rpm:"libxml2-tools~2.13.8~160000.4.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxslt-devel", rpm:"libxslt-devel~1.1.43~160000.4.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxslt-tools", rpm:"libxslt-tools~1.1.43~160000.4.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxslt1", rpm:"libxslt1~1.1.43~160000.4.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python313-libxml2", rpm:"python313-libxml2~2.13.8~160000.4.1", rls:"SLES16.0.0"))) {
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
