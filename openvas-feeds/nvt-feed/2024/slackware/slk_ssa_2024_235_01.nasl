# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.13.2024.235.01");
  script_cve_id("CVE-2022-1475", "CVE-2022-3109", "CVE-2022-3341", "CVE-2022-3964", "CVE-2022-48434", "CVE-2023-47342", "CVE-2024-7055");
  script_tag(name:"creation_date", value:"2024-08-23 04:09:59 +0000 (Fri, 23 Aug 2024)");
  script_version("2025-06-04T05:40:50+0000");
  script_tag(name:"last_modification", value:"2025-06-04 05:40:50 +0000 (Wed, 04 Jun 2025)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-06-03 17:20:06 +0000 (Tue, 03 Jun 2025)");

  script_name("Slackware: Security Advisory (SSA:2024-235-01)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Slackware Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/slackware_linux", "ssh/login/slackpack", re:"ssh/login/release=SLK15\.0");

  script_xref(name:"Advisory-ID", value:"SSA:2024-235-01");
  script_xref(name:"URL", value:"http://www.slackware.com/security/viewer.php?l=slackware-security&y=2024&m=slackware-security.335929");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2022-1475");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2022-3109");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2022-3341");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2022-3964");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2022-48434");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2023-47342");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2024-7055");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ffmpeg' package(s) announced via the SSA:2024-235-01 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"New ffmpeg packages are available for Slackware 15.0 to fix security issues.


Here are the details from the Slackware 15.0 ChangeLog:
+--------------------------+
patches/packages/ffmpeg-4.4.5-i586-1_slack15.0.txz: Upgraded.
 This update addresses several vulnerabilities in FFmpeg which could result
 in denial of service, or potentially the execution of arbitrary code if
 malformed files/streams are processed.
 Thanks to pbslxw for the heads-up.
 For more information, see:
 [links moved to references]
 (* Security fix *)
+--------------------------+");

  script_tag(name:"affected", value:"'ffmpeg' package(s) on Slackware 15.0.");

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

  if(!isnull(res = isslkpkgvuln(pkg:"ffmpeg", ver:"4.4.5-i586-1_slack15.0", rls:"SLK15.0"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"ffmpeg", ver:"4.4.5-x86_64-1_slack15.0", rls:"SLK15.0"))) {
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
