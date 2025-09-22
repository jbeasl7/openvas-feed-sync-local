# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833895");
  script_version("2025-02-26T05:38:41+0000");
  script_cve_id("CVE-2023-22643");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-02-14 23:29:13 +0000 (Tue, 14 Feb 2023)");
  script_tag(name:"creation_date", value:"2024-03-04 07:16:01 +0000 (Mon, 04 Mar 2024)");
  script_name("openSUSE: Security Advisory for libzypp (SUSE-SU-2023:0095-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.4");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:0095-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/MUFI5LNCI6T7VCBA4QD642KDVGDPPOZE");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libzypp'
  package(s) announced via the SUSE-SU-2023:0095-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for libzypp-plugin-appdata fixes the following issues:

  - CVE-2023-22643: Fixed potential shell injection related to malicious
       repo names (bsc#1206836).");

  script_tag(name:"affected", value:"'libzypp' package(s) on openSUSE Leap 15.4.");

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

  if(!isnull(res = isrpmvuln(pkg:"libzypp-plugin-appdata", rpm:"libzypp-plugin-appdata~1.0.1+git.20180426~150400.18.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openSUSE-appdata-extra", rpm:"openSUSE-appdata-extra~1.0.1+git.20180426~150400.18.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libzypp-plugin-appdata", rpm:"libzypp-plugin-appdata~1.0.1+git.20180426~150400.18.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openSUSE-appdata-extra", rpm:"openSUSE-appdata-extra~1.0.1+git.20180426~150400.18.3.1", rls:"openSUSELeap15.4"))) {
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