# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856549");
  script_version("2025-02-26T05:38:41+0000");
  script_cve_id("CVE-2023-22313");
  script_tag(name:"cvss_base", value:"1.4");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:M/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-11-14 19:15:17 +0000 (Tue, 14 Nov 2023)");
  script_tag(name:"creation_date", value:"2024-10-10 04:00:30 +0000 (Thu, 10 Oct 2024)");
  script_name("openSUSE: Security Advisory for qatlib (SUSE-SU-2024:3558-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.4");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:3558-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/XSWYOI7MDEWEA7SHS7V2VMPEV4EU3QHM");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'qatlib'
  package(s) announced via the SUSE-SU-2024:3558-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for qatlib fixes the following issues:

  * CVE-2023-22313: Fixed a local information disclosure due to improper buffer
      restrictions (bsc#1217158).");

  script_tag(name:"affected", value:"'qatlib' package(s) on openSUSE Leap 15.4.");

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

if(release == "openSUSELeap15.4") {

  if(!isnull(res = isrpmvuln(pkg:"qatlib-debugsource", rpm:"qatlib-debugsource~21.08.0~150400.3.3.3", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qatlib-debuginfo", rpm:"qatlib-debuginfo~21.08.0~150400.3.3.3", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qatlib-devel", rpm:"qatlib-devel~21.08.0~150400.3.3.3", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qatlib", rpm:"qatlib~21.08.0~150400.3.3.3", rls:"openSUSELeap15.4"))) {
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