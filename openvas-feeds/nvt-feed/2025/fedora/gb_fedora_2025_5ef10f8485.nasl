# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2025.5101102101028485");
  script_cve_id("CVE-2023-45676", "CVE-2023-45677", "CVE-2023-45679", "CVE-2023-45680", "CVE-2023-45682");
  script_tag(name:"creation_date", value:"2025-01-23 04:08:36 +0000 (Thu, 23 Jan 2025)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-10-26 22:44:51 +0000 (Thu, 26 Oct 2023)");

  script_name("Fedora: Security Advisory (FEDORA-2025-5ef10f8485)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC40");

  script_xref(name:"Advisory-ID", value:"FEDORA-2025-5ef10f8485");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2025-5ef10f8485");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2337428");
  script_xref(name:"URL", value:"https://github.com/icculus/SDL_sound/releases/tag/v2.0.4");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'SDL2_sound' package(s) announced via the FEDORA-2025-5ef10f8485 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Latest stable release from upstream. Changelog: [link moved to references] . NOTE: dr_libs are unbundled.

Fixes:
CVE-2023-45676: Multi-byte write heap buffer overflow in start_decoder()
CVE-2023-45677: Heap buffer out of bounds write in start_decoder()
CVE-2023-45679: Attempt to free an uninitialized memory pointer in vorbis_deinit()
CVE-2023-45680: Null pointer dereference in vorbis_deinit()
CVE-2023-45679: Attempt to free an uninitialized memory pointer in vorbis_deinit()
CVE-2023-45680: Null pointer dereference in vorbis_deinit()
CVE-2023-45682: Wild address read in vorbis_decode_packet_rest()");

  script_tag(name:"affected", value:"'SDL2_sound' package(s) on Fedora 40.");

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

if(release == "FC40") {

  if(!isnull(res = isrpmvuln(pkg:"SDL2_sound", rpm:"SDL2_sound~2.0.4~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"SDL2_sound-debuginfo", rpm:"SDL2_sound-debuginfo~2.0.4~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"SDL2_sound-debugsource", rpm:"SDL2_sound-debugsource~2.0.4~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"SDL2_sound-devel", rpm:"SDL2_sound-devel~2.0.4~1.fc40", rls:"FC40"))) {
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
