# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.18.1.2025.0101.1");
  script_cve_id("CVE-2025-1744", "CVE-2025-1864");
  script_tag(name:"creation_date", value:"2025-03-24 14:23:04 +0000 (Mon, 24 Mar 2025)");
  script_version("2025-07-02T05:41:52+0000");
  script_tag(name:"last_modification", value:"2025-07-02 05:41:52 +0000 (Wed, 02 Jul 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-07-01 14:55:32 +0000 (Tue, 01 Jul 2025)");

  script_name("openSUSE Security Advisory (openSUSE-SU-2025:0101-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.6");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2025:0101-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/HIV7NQ4GTDLGOADVK37OYTIHBMTC3O3W/");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1238075");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1238451");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'radare2' package(s) announced via the openSUSE-SU-2025:0101-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for radare2 fixes the following issues:

- CVE-2025-1864: Fix buffer overflow and potential code execution. (boo#1238451)
- CVE-2025-1744: Fix heap-based buffer over-read or buffer overflow. (boo#1238075)");

  script_tag(name:"affected", value:"'radare2' package(s) on openSUSE Leap 15.6.");

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

if(release == "openSUSELeap15.6") {

  if(!isnull(res = isrpmvuln(pkg:"radare2", rpm:"radare2~5.9.8~bp156.4.9.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"radare2-devel", rpm:"radare2-devel~5.9.8~bp156.4.9.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"radare2-zsh-completion", rpm:"radare2-zsh-completion~5.9.8~bp156.4.9.1", rls:"openSUSELeap15.6"))) {
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
