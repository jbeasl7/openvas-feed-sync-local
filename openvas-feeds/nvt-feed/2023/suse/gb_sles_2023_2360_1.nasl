# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2023.2360.1");
  script_cve_id("CVE-2021-36980", "CVE-2022-32166", "CVE-2022-4337", "CVE-2022-4338");
  script_tag(name:"creation_date", value:"2023-06-05 04:22:34 +0000 (Mon, 05 Jun 2023)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-01-14 04:36:17 +0000 (Sat, 14 Jan 2023)");

  script_name("SUSE: Security Advisory (SUSE-SU-2023:2360-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:2360-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2023/suse-su-20232360-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1188524");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1203865");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1206580");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1206581");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2023-June/015046.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openvswitch' package(s) announced via the SUSE-SU-2023:2360-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for openvswitch fixes the following issues:

- CVE-2022-4338: Fixed Integer Underflow in Organization Specific TLV (bsc#1206580).
- CVE-2022-4337: Fixed Out-of-Bounds Read in Organization Specific TLV (bsc#1206581).
- CVE-2022-32166: Fixed a out of bounds read in minimask_equal() (bsc#1203865).
- CVE-2021-36980: Fixed a use-after-free issue during the decoding of a RAW_ENCAP action (bsc#1188524).");

  script_tag(name:"affected", value:"'openvswitch' package(s) on SUSE Linux Enterprise Server 12-SP4, SUSE Linux Enterprise Server for SAP Applications 12-SP4.");

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

if(release == "SLES12.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"libopenvswitch-2_8-0", rpm:"libopenvswitch-2_8-0~2.8.10~4.33.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openvswitch", rpm:"openvswitch~2.8.10~4.33.1", rls:"SLES12.0SP4"))) {
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
