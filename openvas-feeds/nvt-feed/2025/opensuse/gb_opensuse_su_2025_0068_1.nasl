# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.18.1.2025.0068.1");
  script_cve_id("CVE-2025-25472", "CVE-2025-25474", "CVE-2025-25475");
  script_tag(name:"creation_date", value:"2025-02-24 04:07:13 +0000 (Mon, 24 Feb 2025)");
  script_version("2025-02-24T05:38:04+0000");
  script_tag(name:"last_modification", value:"2025-02-24 05:38:04 +0000 (Mon, 24 Feb 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("openSUSE Security Advisory (openSUSE-SU-2025:0068-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.6");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2025:0068-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/KAE4A7GATAL6JEEG3UTXCDTV3MRMCJX2/");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1237355");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1237365");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1237369");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'dcmtk' package(s) announced via the openSUSE-SU-2025:0068-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for dcmtk fixes the following issues:

- CVE-2025-25472: Fixed a denial of service via a crafted DCM file (boo#1237369).
- CVE-2025-25474: Fixed a denial of service via a crafted DICOM file (boo#1237365).
- CVE-2025-25475: Fixed a buffer overflow via the component /dcmimgle/diinpxt.h (boo#1237355).");

  script_tag(name:"affected", value:"'dcmtk' package(s) on openSUSE Leap 15.6.");

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

  if(!isnull(res = isrpmvuln(pkg:"dcmtk", rpm:"dcmtk~3.6.9~bp156.4.6.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dcmtk-devel", rpm:"dcmtk-devel~3.6.9~bp156.4.6.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdcmtk19", rpm:"libdcmtk19~3.6.9~bp156.4.6.1", rls:"openSUSELeap15.6"))) {
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
