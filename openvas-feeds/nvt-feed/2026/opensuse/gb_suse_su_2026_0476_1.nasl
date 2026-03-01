# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.18.2.2026.0476.1");
  script_cve_id("CVE-2026-21226");
  script_tag(name:"creation_date", value:"2026-02-16 04:43:46 +0000 (Mon, 16 Feb 2026)");
  script_version("2026-02-16T06:02:08+0000");
  script_tag(name:"last_modification", value:"2026-02-16 06:02:08 +0000 (Mon, 16 Feb 2026)");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2026-01-13 19:16:23 +0000 (Tue, 13 Jan 2026)");

  script_name("openSUSE Security Advisory (SUSE-SU-2026:0476-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.6");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2026:0476-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2026/suse-su-20260476-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1257703");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2026-February/024138.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python-azure-core' package(s) announced via the SUSE-SU-2026:0476-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for python-azure-core fixes the following issues:

- CVE-2026-21226: Fixed deserialization of untrusted data which may allow an authorized attacker to execute code over a network. (bsc#1257703)");

  script_tag(name:"affected", value:"'python-azure-core' package(s) on openSUSE Leap 15.6.");

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

  if(!isnull(res = isrpmvuln(pkg:"python311-azure-core", rpm:"python311-azure-core~1.30.0~150400.11.6.1", rls:"openSUSELeap15.6"))) {
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
