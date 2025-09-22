# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2020.3841.1");
  script_cve_id("CVE-2018-10873", "CVE-2018-10893");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-11-15 13:49:08 +0000 (Thu, 15 Nov 2018)");

  script_name("SUSE: Security Advisory (SUSE-SU-2020:3841-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2020:3841-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2020/suse-su-20203841-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1101295");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1104448");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2020-December/008078.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'spice-gtk' package(s) announced via the SUSE-SU-2020:3841-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for spice-gtk fixes the following issues:

- CVE-2018-10873: Fixed a potential heap corruption when demarshalling (bsc#1104448)
- CVE-2018-10893: Fixed a buffer overflow on image lz checks (bsc#1101295)");

  script_tag(name:"affected", value:"'spice-gtk' package(s) on SUSE Linux Enterprise Server 12-SP2, SUSE Linux Enterprise Server for SAP Applications 12-SP2.");

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

if(release == "SLES12.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"libspice-client-glib-2_0-8", rpm:"libspice-client-glib-2_0-8~0.31~9.10.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libspice-client-glib-helper", rpm:"libspice-client-glib-helper~0.31~9.10.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libspice-client-gtk-2_0-4", rpm:"libspice-client-gtk-2_0-4~0.31~9.10.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libspice-client-gtk-3_0-4", rpm:"libspice-client-gtk-3_0-4~0.31~9.10.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libspice-controller0", rpm:"libspice-controller0~0.31~9.10.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1_0-SpiceClientGlib-2_0", rpm:"typelib-1_0-SpiceClientGlib-2_0~0.31~9.10.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1_0-SpiceClientGtk-3_0", rpm:"typelib-1_0-SpiceClientGtk-3_0~0.31~9.10.1", rls:"SLES12.0SP2"))) {
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
