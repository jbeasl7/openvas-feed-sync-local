# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856103");
  script_cve_id("CVE-2024-28130");
  script_tag(name:"creation_date", value:"2024-04-26 01:02:06 +0000 (Fri, 26 Apr 2024)");
  script_version("2025-02-26T05:38:40+0000");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:40 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-04-23 15:15:49 +0000 (Tue, 23 Apr 2024)");

  script_name("openSUSE Security Advisory (openSUSE-SU-2024:0113-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.5");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2024:0113-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/XXL36P7M6YZRV6UPSI2YMI4FH6YX6H24/");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220809");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223324");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'dcmtk' package(s) announced via the openSUSE-SU-2024:0113-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for dcmtk fixes the following issues:

* Fixed incorrect type conversion in the DVPSSoftcopyVOI_PList:createFromImage functionality of OFFIS DCMTK (boo#1223324, CVE-2024-28130)

- Add missing requirements for dcmtk-devel (boo#1220809)

- Update to 3.6.8
 See DOCS/CHANGES.368 for the full list of changes");

  script_tag(name:"affected", value:"'dcmtk' package(s) on openSUSE Leap 15.5.");

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

if(release == "openSUSELeap15.5") {

  if(!isnull(res = isrpmvuln(pkg:"dcmtk", rpm:"dcmtk~3.6.8~bp155.3.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dcmtk-devel", rpm:"dcmtk-devel~3.6.8~bp155.3.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdcmtk18", rpm:"libdcmtk18~3.6.8~bp155.3.3.1", rls:"openSUSELeap15.5"))) {
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
