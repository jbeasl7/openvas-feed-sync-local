# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2024.3097.1");
  script_cve_id("CVE-2023-39325", "CVE-2023-44487", "CVE-2023-45288", "CVE-2024-24786");
  script_tag(name:"creation_date", value:"2024-09-04 04:26:54 +0000 (Wed, 04 Sep 2024)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-10-13 19:32:37 +0000 (Fri, 13 Oct 2023)");

  script_name("SUSE: Security Advisory (SUSE-SU-2024:3097-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:3097-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2024/suse-su-20243097-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229858");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229867");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229869");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-updates/2024-September/036775.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kubernetes1.28' package(s) announced via the SUSE-SU-2024:3097-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for kubernetes1.28 fixes the following issues:

Update kubernetes to version 1.28.13:
- CVE-2024-24786: Fixed infinite loop in protojson.Unmarshal in golang-protobuf (bsc#1229867)
- CVE-2023-39325: Fixed a flaw that can lead to a DoS due to a rapid stream resets causing excessive work. This is also known as CVE-2023-44487. (bsc#1229869)
- CVE-2023-45288: Fixed denial of service due to close connections when receiving too many headers in net/http and x/net/http2 (bsc#1229869)
- CVE-2023-44487: Fixed HTTP/2 Rapid Reset attack in net/http (bsc#1229869)

Other fixes:
- Update go to version v1.22.5 (bsc#1229858)");

  script_tag(name:"affected", value:"'kubernetes1.28' package(s) on SUSE Linux Enterprise Server 15-SP4, SUSE Linux Enterprise Server for SAP Applications 15-SP4.");

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

if(release == "SLES15.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"kubernetes1.28-client", rpm:"kubernetes1.28-client~1.28.13~150400.9.8.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kubernetes1.28-client-common", rpm:"kubernetes1.28-client-common~1.28.13~150400.9.8.1", rls:"SLES15.0SP4"))) {
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
