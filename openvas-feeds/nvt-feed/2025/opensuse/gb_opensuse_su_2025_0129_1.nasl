# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.18.1.2025.0129.1");
  script_cve_id("CVE-2024-35176", "CVE-2024-39908", "CVE-2024-41123", "CVE-2024-41946", "CVE-2024-43398", "CVE-2024-49761");
  script_tag(name:"creation_date", value:"2025-04-21 04:06:46 +0000 (Mon, 21 Apr 2025)");
  script_version("2025-05-01T05:40:03+0000");
  script_tag(name:"last_modification", value:"2025-05-01 05:40:03 +0000 (Thu, 01 May 2025)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-11-05 16:41:46 +0000 (Tue, 05 Nov 2024)");

  script_name("openSUSE Security Advisory (openSUSE-SU-2025:0129-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.6");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2025:0129-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/DGKHOJBF7CZTZV4MBBSARWRERGVICQZ5/");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224390");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1228072");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1228794");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1228799");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229673");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232440");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'rubygem-rexml' package(s) announced via the openSUSE-SU-2025:0129-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"rubygem-rexml was updated to 3.3.9:

- fixes CVE-2024-49761, CVE-2024-43398, CVE-2024-41946,
 CVE-2024-41123, CVE-2024-39908, CVE-2024-35176
- bsc#1232440, bsc#1229673, bsc#1228799, bsc#1228794,
 bsc#1228072, bsc#1224390");

  script_tag(name:"affected", value:"'rubygem-rexml' package(s) on openSUSE Leap 15.6.");

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

  if(!isnull(res = isrpmvuln(pkg:"ruby2.5-rubygem-rexml", rpm:"ruby2.5-rubygem-rexml~3.3.9~bp156.4.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby2.5-rubygem-rexml-doc", rpm:"ruby2.5-rubygem-rexml-doc~3.3.9~bp156.4.3.1", rls:"openSUSELeap15.6"))) {
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
