# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2023.2226.1");
  script_cve_id("CVE-2022-43552", "CVE-2023-23916", "CVE-2023-27533", "CVE-2023-27534", "CVE-2023-27535", "CVE-2023-27536", "CVE-2023-27538", "CVE-2023-28320", "CVE-2023-28321", "CVE-2023-28322");
  script_tag(name:"creation_date", value:"2023-05-18 04:26:20 +0000 (Thu, 18 May 2023)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-04-07 16:23:46 +0000 (Fri, 07 Apr 2023)");

  script_name("SUSE: Security Advisory (SUSE-SU-2023:2226-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP1)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:2226-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2023/suse-su-20232226-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1206309");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1207992");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1209209");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1209210");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1209211");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1209212");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1209214");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1211231");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1211232");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1211233");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1211339");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-updates/2023-May/029432.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'curl' package(s) announced via the SUSE-SU-2023:2226-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for curl fixes the following issues:

- CVE-2023-28320: Fixed siglongjmp race condition (bsc#1211231).
- CVE-2023-28321: Fixed IDN wildcard matching (bsc#1211232).
- CVE-2023-28322: Fixed POST-after-PUT confusion (bsc#1211233).
- CVE-2023-27533: Fixed TELNET option IAC injection (bsc#1209209).
- CVE-2023-27534: Fixed SFTP path ~ resolving discrepancy (bsc#1209210).
- CVE-2023-27535: Fixed FTP too eager connection reuse (bsc#1209211).
- CVE-2023-27536: Fixed GSS delegation too eager connection reuse (bsc#1209212).
- CVE-2023-27538: Fixed SSH connection too eager reuse still (bsc#1209214).
- CVE-2022-43552: HTTP Proxy deny use-after-free (bsc#1206309).
- CVE-2023-23916: Fixed HTTP multi-header compression denial of service (bsc#1207992).");

  script_tag(name:"affected", value:"'curl' package(s) on SUSE Linux Enterprise Server 15-SP1, SUSE Linux Enterprise Server for SAP Applications 15-SP1.");

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

if(release == "SLES15.0SP1") {

  if(!isnull(res = isrpmvuln(pkg:"curl", rpm:"curl~7.60.0~150000.51.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcurl-devel", rpm:"libcurl-devel~7.60.0~150000.51.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcurl4-32bit", rpm:"libcurl4-32bit~7.60.0~150000.51.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcurl4", rpm:"libcurl4~7.60.0~150000.51.1", rls:"SLES15.0SP1"))) {
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
