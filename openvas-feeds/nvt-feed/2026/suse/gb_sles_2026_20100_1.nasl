# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2026.20100.1");
  script_cve_id("CVE-2025-41244");
  script_tag(name:"creation_date", value:"2026-01-26 08:39:16 +0000 (Mon, 26 Jan 2026)");
  script_version("2026-01-28T05:49:43+0000");
  script_tag(name:"last_modification", value:"2026-01-28 05:49:43 +0000 (Wed, 28 Jan 2026)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("SUSE: Security Advisory (SUSE-SU-2026:20100-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES16\.0\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2026:20100-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2026/suse-su-202620100-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1250373");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1250692");
  script_xref(name:"URL", value:"https://github.com/vmware/open-vm-tools/blob/stable-13.0.5/ReleaseNotes.md");
  script_xref(name:"URL", value:"https://github.com/vmware/open-vm-tools/blob/stable-13.0.5/open-vm-tools/ChangeLog");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2026-January/023883.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Security update of open-vm-tools' package(s) announced via the SUSE-SU-2026:20100-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for open-vm-tools fixes the following issues:

Update to open-vm-tools 13.0.5 based on build 24915695. (boo#1250692):

Please refer to the Release Notes at [link moved to references].

The granular changes that have gone into the open-vm-tools 13.0.5 release are in the ChangeLog at [link moved to references].

There are no new features in the open-vm-tools 13.0.5 release. This is primarily a maintenance release that addresses a security issue.

This release resolves and includes the patch for CVE-2025-41244. For more information on this vulnerability and its impact on Broadcom products,
see VMSA-2025-0015.

A minor enhancement has been made for Guest OS Customization. The DeployPkg plugin has been updated to use 'systemctl reboot', if available.

For a more complete list of issues addressed in this release, see the What's New and Resolved Issues section of the Release Notes.");

  script_tag(name:"affected", value:"'Security update of open-vm-tools' package(s) on SUSE Linux Enterprise Server 16.0, SUSE Linux Enterprise Server for SAP Applications 16.0.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "SLES16.0.0") {

  if(!isnull(res = isrpmvuln(pkg:"libvmtools-devel", rpm:"libvmtools-devel~13.0.5~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvmtools0", rpm:"libvmtools0~13.0.5~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"open-vm-tools", rpm:"open-vm-tools~13.0.5~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"open-vm-tools-containerinfo", rpm:"open-vm-tools-containerinfo~13.0.5~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"open-vm-tools-desktop", rpm:"open-vm-tools-desktop~13.0.5~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"open-vm-tools-sdmp", rpm:"open-vm-tools-sdmp~13.0.5~160000.1.1", rls:"SLES16.0.0"))) {
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
