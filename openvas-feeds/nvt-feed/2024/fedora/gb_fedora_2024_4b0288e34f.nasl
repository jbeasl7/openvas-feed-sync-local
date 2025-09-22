# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2024.498028810134102");
  script_tag(name:"creation_date", value:"2024-12-27 04:08:39 +0000 (Fri, 27 Dec 2024)");
  script_version("2024-12-27T15:39:18+0000");
  script_tag(name:"last_modification", value:"2024-12-27 15:39:18 +0000 (Fri, 27 Dec 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Fedora: Security Advisory (FEDORA-2024-4b0288e34f)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC40");

  script_xref(name:"Advisory-ID", value:"FEDORA-2024-4b0288e34f");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2024-4b0288e34f");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'dr_libs' package(s) announced via the FEDORA-2024-4b0288e34f advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Update to 0^20241216git660795b

- dr_flac 0.12.43: Fix a possible buffer overflow during decoding. Improve detection of ARM64EC.
- dr_mp3 0.6.40: Improve detection of ARM64EC
- dr_wav 0.13.17: Fix a possible crash when reading from MS-ADPCM encoded files. Improve detection of ARM64EC.

----

Add a SourceLicense field");

  script_tag(name:"affected", value:"'dr_libs' package(s) on Fedora 40.");

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

  if(!isnull(res = isrpmvuln(pkg:"dr_flac-devel", rpm:"dr_flac-devel~0.12.43^20241216git660795b~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dr_libs", rpm:"dr_libs~0^20241216git660795b~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dr_libs-devel", rpm:"dr_libs-devel~0^20241216git660795b~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dr_libs-doc", rpm:"dr_libs-doc~0^20241216git660795b~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dr_mp3-devel", rpm:"dr_mp3-devel~0.6.40^20241216git660795b~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dr_wav-devel", rpm:"dr_wav-devel~0.13.17^20241216git660795b~1.fc40", rls:"FC40"))) {
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
