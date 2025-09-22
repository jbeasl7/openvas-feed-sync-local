# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.13.2024.110.01");
  script_cve_id("CVE-2024-32039", "CVE-2024-32040", "CVE-2024-32041", "CVE-2024-32458", "CVE-2024-32459", "CVE-2024-32460");
  script_tag(name:"creation_date", value:"2024-04-22 04:20:52 +0000 (Mon, 22 Apr 2024)");
  script_version("2025-02-05T05:38:26+0000");
  script_tag(name:"last_modification", value:"2025-02-05 05:38:26 +0000 (Wed, 05 Feb 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-02-04 17:58:52 +0000 (Tue, 04 Feb 2025)");

  script_name("Slackware: Security Advisory (SSA:2024-110-01)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Slackware Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/slackware_linux", "ssh/login/slackpack", re:"ssh/login/release=SLK(15\.0|current)");

  script_xref(name:"Advisory-ID", value:"SSA:2024-110-01");
  script_xref(name:"URL", value:"http://www.slackware.com/security/viewer.php?l=slackware-security&y=2024&m=slackware-security.389933");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2024-32039");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2024-32040");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2024-32041");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2024-32458");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2024-32459");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2024-32460");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'freerdp' package(s) announced via the SSA:2024-110-01 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"New freerdp packages are available for Slackware 15.0 and -current to
fix security issues.


Here are the details from the Slackware 15.0 ChangeLog:
+--------------------------+
patches/packages/freerdp-2.11.6-i586-1_slack15.0.txz: Upgraded.
 This release is a security release and addresses multiple issues:
 [Low] OutOfBound Read in zgfx_decompress_segment.
 [Moderate] Integer overflow & OutOfBound Write in
 clear_decompress_residual_data.
 [Low] integer underflow in nsc_rle_decode.
 [Low] OutOfBound Read in planar_skip_plane_rle.
 [Low] OutOfBound Read in ncrush_decompress.
 [Low] OutOfBound Read in interleaved_decompress.
 For more information, see:
 [links moved to references]
 (* Security fix *)
+--------------------------+");

  script_tag(name:"affected", value:"'freerdp' package(s) on Slackware 15.0, Slackware current.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-slack.inc");

release = slk_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "SLK15.0") {

  if(!isnull(res = isslkpkgvuln(pkg:"freerdp", ver:"2.11.6-i586-1_slack15.0", rls:"SLK15.0"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"freerdp", ver:"2.11.6-x86_64-1_slack15.0", rls:"SLK15.0"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLKcurrent") {

  if(!isnull(res = isslkpkgvuln(pkg:"freerdp", ver:"2.11.6-i586-1", rls:"SLKcurrent"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"freerdp", ver:"2.11.6-x86_64-1", rls:"SLKcurrent"))) {
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
