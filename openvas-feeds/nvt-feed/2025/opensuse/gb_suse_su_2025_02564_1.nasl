# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.18.2.2025.02564.1");
  script_cve_id("CVE-2025-32441", "CVE-2025-46727");
  script_tag(name:"creation_date", value:"2025-08-01 04:28:07 +0000 (Fri, 01 Aug 2025)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-06-17 19:44:47 +0000 (Tue, 17 Jun 2025)");

  script_name("openSUSE Security Advisory (SUSE-SU-2025:02564-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.6");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:02564-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-202502564-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1242893");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1242898");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1244166");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-updates/2025-July/040971.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'rmt-server' package(s) announced via the SUSE-SU-2025:02564-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for rmt-server fixes the following issues:

- Update to version 2.23
- CVE-2025-46727: Fixed Unbounded-Parameter DoS in Rack:QueryParser. (bsc#1242893)
- CVE-2025-32441: Fixed a bug where simultaneous rack requests can restore a deleted rack session. (bsc#1242898)");

  script_tag(name:"affected", value:"'rmt-server' package(s) on openSUSE Leap 15.6.");

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

  if(!isnull(res = isrpmvuln(pkg:"rmt-server", rpm:"rmt-server~2.23~150500.3.34.2", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rmt-server-config", rpm:"rmt-server-config~2.23~150500.3.34.2", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rmt-server-pubcloud", rpm:"rmt-server-pubcloud~2.23~150500.3.34.2", rls:"openSUSELeap15.6"))) {
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
