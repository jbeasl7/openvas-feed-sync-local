# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2019.0480.1");
  script_cve_id("CVE-2018-19637", "CVE-2018-19638", "CVE-2018-19639", "CVE-2018-19640");
  script_tag(name:"creation_date", value:"2021-06-09 14:57:30 +0000 (Wed, 09 Jun 2021)");
  script_version("2024-02-02T14:37:50+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:50 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-03-05 21:48:48 +0000 (Tue, 05 Mar 2019)");

  script_name("SUSE: Security Advisory (SUSE-SU-2019:0480-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2019:0480-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2019/suse-su-20190480-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'supportutils' package(s) announced via the SUSE-SU-2019:0480-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for supportutils fixes the following issues:

Security issues fixed:
CVE-2018-19640: Fixed an issue where users could kill arbitrary
 processes (bsc#1118463).

CVE-2018-19638: Fixed an issue where users could overwrite arbitrary log
 files (bsc#1118460).

CVE-2018-19639: Fixed a code execution if run with -v (bsc#1118462).

CVE-2018-19637: Fixed an issue where static temporary filename could
 allow overwriting of files (bsc#1117776).

Other issues fixed:
Fixed invalid exit code commands (bsc#1125666).

Included additional SUSE separation (bsc#1125609).

Merged added listing of locked packes by zypper.

Exclude pam.txt per GDPR by default (bsc#1112461).

Clarified -x functionality in supportconfig(8) (bsc#1115245).

udev service and provide the whole journal content in supportconfig
 (bsc#1051797).

supportconfig collects tuned profile settings (bsc#1071545).

sfdisk -d no disk device specified (bsc#1043311).

Added vulnerabilities status check in basic-health.txt (bsc#1105849).

Added only sched_domain from cpu0.

Blacklist sched_domain from proc.txt (bsc#1046681).

Added firewall-cmd info.

Add ls -lA --time-style=long-iso /etc/products.d/

Dump lsof errors.

Added corosync status to ha_info.

Dump find errors in ib_info.");

  script_tag(name:"affected", value:"'supportutils' package(s) on SUSE Linux Enterprise Module for Basesystem 15.");

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

if(release == "SLES15.0") {

  if(!isnull(res = isrpmvuln(pkg:"supportutils", rpm:"supportutils~3.1~5.7.1", rls:"SLES15.0"))) {
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
