# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.18.1.2025.0037.1");
  script_cve_id("CVE-2023-45676", "CVE-2023-45677", "CVE-2023-45679", "CVE-2023-45680", "CVE-2023-45681", "CVE-2023-45682");
  script_tag(name:"creation_date", value:"2025-02-18 11:01:57 +0000 (Tue, 18 Feb 2025)");
  script_version("2025-02-26T05:38:41+0000");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-10-26 22:45:25 +0000 (Thu, 26 Oct 2023)");

  script_name("openSUSE Security Advisory (openSUSE-SU-2025:0037-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.6");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2025:0037-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/PYKIGUIZT6TXJBJESQGK4RWVLRA2YLO4/");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1216478");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'SDL2_sound' package(s) announced via the openSUSE-SU-2025:0037-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for SDL2_sound fixes the following issues:

- Update to release 2.0.4:
 * Update bundled stb_vorbis to address CVE-2023-45676,
 CVE-2023-45677, CVE-2023-45679, CVE-2023-45680,
 CVE-2023-45681, CVE-2023-45682.

- Update to release 2.0.2
 * No further changes from the last snapshot 2.0.1+g60");

  script_tag(name:"affected", value:"'SDL2_sound' package(s) on openSUSE Leap 15.6.");

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

  if(!isnull(res = isrpmvuln(pkg:"SDL2_sound-devel", rpm:"SDL2_sound-devel~2.0.4~bp156.2.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libSDL2_sound2", rpm:"libSDL2_sound2~2.0.4~bp156.2.3.1", rls:"openSUSELeap15.6"))) {
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
