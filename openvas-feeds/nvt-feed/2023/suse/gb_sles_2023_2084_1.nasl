# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2023.2084.1");
  script_cve_id("CVE-2022-28737");
  script_tag(name:"creation_date", value:"2023-05-09 04:23:35 +0000 (Tue, 09 May 2023)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-07-28 15:33:58 +0000 (Fri, 28 Jul 2023)");

  script_name("SUSE: Security Advisory (SUSE-SU-2023:2084-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:2084-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2023/suse-su-20232084-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1210382");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2023-May/014772.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'shim' package(s) announced via the SUSE-SU-2023:2084-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for shim fixes the following issues:

- CVE-2022-28737 was missing as reference previously.

- Upgrade shim-install for bsc#1210382

 After closing Leap-gap project since Leap 15.3, openSUSE Leap direct
 uses shim from SLE. So the ca_string is 'SUSE Linux Enterprise Secure Boot
 CA1', not 'openSUSE Secure Boot CA1'. It causes that the update_boot=no,
 so all files in /boot/efi/EFI/boot are not updated.

 Logic was added that is using ID field in os-release for
 checking Leap distro and set ca_string to 'SUSE Linux Enterprise Secure
 Boot CA1'. Then /boot/efi/EFI/boot/* can also be updated.");

  script_tag(name:"affected", value:"'shim' package(s) on SUSE Linux Enterprise Server 15-SP3, SUSE Linux Enterprise Server for SAP Applications 15-SP3.");

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

if(release == "SLES15.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"shim", rpm:"shim~15.7~150300.4.16.1", rls:"SLES15.0SP3"))) {
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
