# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2025.03348.1");
  script_cve_id("CVE-2024-13978", "CVE-2025-8534", "CVE-2025-8961", "CVE-2025-9165");
  script_tag(name:"creation_date", value:"2025-09-25 15:06:07 +0000 (Thu, 25 Sep 2025)");
  script_version("2025-09-26T05:38:41+0000");
  script_tag(name:"last_modification", value:"2025-09-26 05:38:41 +0000 (Fri, 26 Sep 2025)");
  script_tag(name:"cvss_base", value:"1.7");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:L");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-08-19 20:15:37 +0000 (Tue, 19 Aug 2025)");

  script_name("SUSE: Security Advisory (SUSE-SU-2025:03348-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP6)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:03348-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-202503348-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1247581");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1247582");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1248117");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1248330");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-updates/2025-September/041835.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'tiff' package(s) announced via the SUSE-SU-2025:03348-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for tiff fixes the following issues:

- CVE-2025-9165: local execution manipulation leading to memory leak (bsc#1248330).
- CVE-2024-13978: null pointer dereference in component fax2ps (bsc#1247581)
- CVE-2025-8534: null pointer dereference in function PS_Lvl2page (bsc#1247582).
- CVE-2025-8961: segmentation fault via main function of tiffcrop utility (bsc#1248117).");

  script_tag(name:"affected", value:"'tiff' package(s) on SUSE Linux Enterprise Server 15-SP6.");

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

if(release == "SLES15.0SP6") {

  if(!isnull(res = isrpmvuln(pkg:"libtiff-devel", rpm:"libtiff-devel~4.7.0~150600.3.18.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtiff6-32bit", rpm:"libtiff6-32bit~4.7.0~150600.3.18.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtiff6", rpm:"libtiff6~4.7.0~150600.3.18.1", rls:"SLES15.0SP6"))) {
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
