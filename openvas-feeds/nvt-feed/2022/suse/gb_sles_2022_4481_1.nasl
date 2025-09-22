# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2022.4481.1");
  script_cve_id("CVE-2022-4283", "CVE-2022-46340", "CVE-2022-46341", "CVE-2022-46342", "CVE-2022-46343", "CVE-2022-46344");
  script_tag(name:"creation_date", value:"2022-12-15 04:18:54 +0000 (Thu, 15 Dec 2022)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-12-19 20:32:49 +0000 (Mon, 19 Dec 2022)");

  script_name("SUSE: Security Advisory (SUSE-SU-2022:4481-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP1)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:4481-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2022/suse-su-20224481-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1205874");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1205875");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1205876");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1205877");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1205878");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1205879");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1206017");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2022-December/013246.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'xorg-x11-server' package(s) announced via the SUSE-SU-2022:4481-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for xorg-x11-server fixes the following issues:

- CVE-2022-46340: Server XTestSwapFakeInput stack overflow (bsc#1205874)
- CVE-2022-46341: Server XIPassiveUngrabDevice out-of-bounds access (bsc#1205877)
- CVE-2022-46342: Server XvdiSelectVideoNotify use-after-free (bsc#1205879)
- CVE-2022-46343: Server ScreenSaverSetAttributes use-after-free (bsc#1205878)
- CVE-2022-46344: Server XIChangeProperty out-of-bounds access (bsc#1205876)
- CVE-2022-4283: Reset the radio_groups pointer to NULL after freeing it (bsc#1206017)
- Xi: return an error from XI property changes if verification failed (bsc#1205875)");

  script_tag(name:"affected", value:"'xorg-x11-server' package(s) on SUSE Linux Enterprise Server 15-SP1, SUSE Linux Enterprise Server for SAP Applications 15-SP1.");

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

if(release == "SLES15.0SP1") {

  if(!isnull(res = isrpmvuln(pkg:"xorg-x11-server", rpm:"xorg-x11-server~1.20.3~150100.14.5.33.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xorg-x11-server-extra", rpm:"xorg-x11-server-extra~1.20.3~150100.14.5.33.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xorg-x11-server-sdk", rpm:"xorg-x11-server-sdk~1.20.3~150100.14.5.33.1", rls:"SLES15.0SP1"))) {
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
