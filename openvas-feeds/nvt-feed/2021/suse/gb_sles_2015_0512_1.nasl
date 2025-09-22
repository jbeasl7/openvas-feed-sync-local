# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2015.0512.1");
  script_cve_id("CVE-2013-7252");
  script_tag(name:"creation_date", value:"2021-06-09 14:58:13 +0000 (Wed, 09 Jun 2021)");
  script_version("2025-08-15T15:42:24+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:24 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("SUSE: Security Advisory (SUSE-SU-2015:0512-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2015:0512-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2015/suse-su-20150512-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/857200");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2015-March/001292.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kdebase4-runtime' package(s) announced via the SUSE-SU-2015:0512-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"kdebase4-runtime has been updated to fix one security issue:

 * CVE-2013-7252: Added gpg based encryption support to kwallet
 (bnc#857200).

Security Issues:

 * CVE-2013-7252
 <[link moved to references]>");

  script_tag(name:"affected", value:"'kdebase4-runtime' package(s) on SUSE Linux Enterprise Desktop 11-SP3, SUSE Linux Enterprise Server 11-SP3, SUSE Linux Enterprise Server for SAP Applications 11-SP3.");

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

  if(!isnull(res = isrpmvuln(pkg:"kde4-l10n-ar", rpm:"kde4-l10n-ar~4.3.5~0.3.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kde4-l10n-bg", rpm:"kde4-l10n-bg~4.3.5~0.3.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kde4-l10n-ca", rpm:"kde4-l10n-ca~4.3.5~0.3.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kde4-l10n-cs", rpm:"kde4-l10n-cs~4.3.5~0.3.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kde4-l10n-csb", rpm:"kde4-l10n-csb~4.3.5~0.3.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kde4-l10n-da", rpm:"kde4-l10n-da~4.3.5~0.3.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kde4-l10n-de", rpm:"kde4-l10n-de~4.3.5~0.3.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kde4-l10n-el", rpm:"kde4-l10n-el~4.3.5~0.3.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kde4-l10n-en_GB", rpm:"kde4-l10n-en_GB~4.3.5~0.3.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kde4-l10n-es", rpm:"kde4-l10n-es~4.3.5~0.3.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kde4-l10n-et", rpm:"kde4-l10n-et~4.3.5~0.3.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kde4-l10n-eu", rpm:"kde4-l10n-eu~4.3.5~0.3.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kde4-l10n-fi", rpm:"kde4-l10n-fi~4.3.5~0.3.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kde4-l10n-fr", rpm:"kde4-l10n-fr~4.3.5~0.3.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kde4-l10n-ga", rpm:"kde4-l10n-ga~4.3.5~0.3.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kde4-l10n-gl", rpm:"kde4-l10n-gl~4.3.5~0.3.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kde4-l10n-hi", rpm:"kde4-l10n-hi~4.3.5~0.3.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kde4-l10n-hu", rpm:"kde4-l10n-hu~4.3.5~0.3.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kde4-l10n-is", rpm:"kde4-l10n-is~4.3.5~0.3.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kde4-l10n-it", rpm:"kde4-l10n-it~4.3.5~0.3.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kde4-l10n-ja", rpm:"kde4-l10n-ja~4.3.5~0.3.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kde4-l10n-kk", rpm:"kde4-l10n-kk~4.3.5~0.3.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kde4-l10n-km", rpm:"kde4-l10n-km~4.3.5~0.3.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kde4-l10n-ko", rpm:"kde4-l10n-ko~4.3.5~0.3.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kde4-l10n-ku", rpm:"kde4-l10n-ku~4.3.5~0.3.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kde4-l10n-lt", rpm:"kde4-l10n-lt~4.3.5~0.3.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kde4-l10n-lv", rpm:"kde4-l10n-lv~4.3.5~0.3.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kde4-l10n-mk", rpm:"kde4-l10n-mk~4.3.5~0.3.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kde4-l10n-ml", rpm:"kde4-l10n-ml~4.3.5~0.3.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kde4-l10n-nb", rpm:"kde4-l10n-nb~4.3.5~0.3.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kde4-l10n-nds", rpm:"kde4-l10n-nds~4.3.5~0.3.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kde4-l10n-nl", rpm:"kde4-l10n-nl~4.3.5~0.3.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kde4-l10n-nn", rpm:"kde4-l10n-nn~4.3.5~0.3.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kde4-l10n-pa", rpm:"kde4-l10n-pa~4.3.5~0.3.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kde4-l10n-pl", rpm:"kde4-l10n-pl~4.3.5~0.3.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kde4-l10n-pt", rpm:"kde4-l10n-pt~4.3.5~0.3.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kde4-l10n-pt_BR", rpm:"kde4-l10n-pt_BR~4.3.5~0.3.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kde4-l10n-ro", rpm:"kde4-l10n-ro~4.3.5~0.3.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kde4-l10n-ru", rpm:"kde4-l10n-ru~4.3.5~0.3.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kde4-l10n-sl", rpm:"kde4-l10n-sl~4.3.5~0.3.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kde4-l10n-sv", rpm:"kde4-l10n-sv~4.3.5~0.3.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kde4-l10n-th", rpm:"kde4-l10n-th~4.3.5~0.3.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kde4-l10n-tr", rpm:"kde4-l10n-tr~4.3.5~0.3.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kde4-l10n-uk", rpm:"kde4-l10n-uk~4.3.5~0.3.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kde4-l10n-wa", rpm:"kde4-l10n-wa~4.3.5~0.3.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kde4-l10n-zh_CN", rpm:"kde4-l10n-zh_CN~4.3.5~0.3.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kde4-l10n-zh_TW", rpm:"kde4-l10n-zh_TW~4.3.5~0.3.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kdebase4-runtime", rpm:"kdebase4-runtime~4.3.5~0.3.1", rls:"SLES11.0SP3"))) {
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
