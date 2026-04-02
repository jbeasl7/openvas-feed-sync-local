# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2026.10011006659991005");
  script_cve_id("CVE-2026-29022");
  script_tag(name:"creation_date", value:"2026-03-12 04:38:33 +0000 (Thu, 12 Mar 2026)");
  script_version("2026-03-13T05:54:58+0000");
  script_tag(name:"last_modification", value:"2026-03-13 05:54:58 +0000 (Fri, 13 Mar 2026)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2026-03-09 18:13:43 +0000 (Mon, 09 Mar 2026)");

  script_name("Fedora: Security Advisory (FEDORA-2026-d1d665c9d5)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC43");

  script_xref(name:"Advisory-ID", value:"FEDORA-2026-d1d665c9d5");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2026-d1d665c9d5");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2444312");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'dr_libs' package(s) announced via the FEDORA-2026-d1d665c9d5 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"dr_flac
=======

v0.13.3 - 2026-01-17
--------------------

- Fix a compiler compatibility issue with some inlined assembly.
- Fix a compilation warning.

dr_mp3
======

v0.7.3 - 2026-01-17
-------------------

- Fix an error in drmp3_open_and_read_pcm_frames_s16() and family when memory
allocation fails.
- Fix some compilation warnings.

dr_wav
======

v0.14.5 - 2026-03-03
--------------------

- Fix a crash when loading files with a malformed 'smpl' chunk.
- Fix a signed overflow bug with the MS-ADPCM decoder.

v0.14.4 - 2026-01-17
--------------------

- Fix some compilation warnings.");

  script_tag(name:"affected", value:"'dr_libs' package(s) on Fedora 43.");

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

if(release == "FC43") {

  if(!isnull(res = isrpmvuln(pkg:"dr_flac-devel", rpm:"dr_flac-devel~0.13.3^20260302.fa931f3~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dr_libs", rpm:"dr_libs~0^20260302.fa931f3~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dr_libs-devel", rpm:"dr_libs-devel~0^20260302.fa931f3~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dr_libs-doc", rpm:"dr_libs-doc~0^20260302.fa931f3~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dr_mp3-devel", rpm:"dr_mp3-devel~0.7.3^20260302.fa931f3~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dr_wav-devel", rpm:"dr_wav-devel~0.14.5^20260302.fa931f3~2.fc43", rls:"FC43"))) {
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
