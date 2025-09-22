# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856927");
  script_cve_id("CVE-2023-41081", "CVE-2024-46544");
  script_tag(name:"creation_date", value:"2025-01-15 05:01:35 +0000 (Wed, 15 Jan 2025)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-09-15 13:26:15 +0000 (Fri, 15 Sep 2023)");

  script_name("openSUSE Security Advisory (SUSE-SU-2025:0102-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.6");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:0102-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-20250102-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1215301");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1230916");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2025-January/020119.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'apache2-mod_jk' package(s) announced via the SUSE-SU-2025:0102-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for apache2-mod_jk fixes the following issues:

- Update to version 1.2.50:
- CVE-2024-46544: Fixed incorrect default permissions vulnerabilitymay that could lead to information disclosure and/or denial of service. (bsc#1230916)
- CVE-2023-41081: Fixed information disclosure in mod_jk. (bsc#1215301)");

  script_tag(name:"affected", value:"'apache2-mod_jk' package(s) on openSUSE Leap 15.6.");

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

  if(!isnull(res = isrpmvuln(pkg:"apache2-mod_jk", rpm:"apache2-mod_jk~1.2.50~150100.6.12.1", rls:"openSUSELeap15.6"))) {
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
