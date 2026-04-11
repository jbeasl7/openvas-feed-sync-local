# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.18.2.2026.1194.1");
  script_cve_id("CVE-2026-33186");
  script_tag(name:"creation_date", value:"2026-04-09 04:48:59 +0000 (Thu, 09 Apr 2026)");
  script_version("2026-04-09T06:11:03+0000");
  script_tag(name:"last_modification", value:"2026-04-09 06:11:03 +0000 (Thu, 09 Apr 2026)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("openSUSE Security Advisory (SUSE-SU-2026:1194-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.6");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2026:1194-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2026/suse-su-20261194-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1259816");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1260265");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-updates/2026-April/045295.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'google-cloud-sap-agent' package(s) announced via the SUSE-SU-2026:1194-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for google-cloud-sap-agent fixes the following issue:

Update to google-cloud-sap-agent 3.12 (bsc#1259816):

- CVE-2026-33186: google.golang.org/grpc: authorization bypass due to improper validation of the HTTP/2: path pseudo-
 header (bsc#1260265).

Changelog:

 * Collect WLM metric `saphanasr_angi_installed` for all OS types.
 * Failure handling: Remove attached disks from CG
 * OTE Status checks for Parameter Manager (SAP Agent)
 * Log command-line arguments in configureinstance.
 * Minor multiple reliability checks and fixes
 * Support custom names for restored disks in hanadiskrestore
 * Add newAttachedDisks to Restorer and detach them on restore failure.
 * Improve unit test coverage for hanadiskbackup and hanadiskrestore
 * Add support for refresh point tests.
 * Refactor HANA disk backup user validation and physical path parsing.
 * Auto updated compiled protocol buffers
 * Parameter Manager integration to SAP Agent
 * Modify collection logic for SAP HANA configuration files.
 * Update workloadagentplatform version and hash.
 * Update WLM Validation metrics to support SAPHanaSR-angi setups.
 * Increment agent version to 3.12.
 * SAP HANA Pacemaker failover settings can come from `SAPHanaController`.
 * Update collection for WLM metric `ha_sr_hook_configured`.
 * Refactor CheckTopology to accept instance number.
 * Use constant backoff with max retries for snapshot group operations.
 * Update workloadagentplatform dependency");

  script_tag(name:"affected", value:"'google-cloud-sap-agent' package(s) on openSUSE Leap 15.6.");

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

  if(!isnull(res = isrpmvuln(pkg:"google-cloud-sap-agent", rpm:"google-cloud-sap-agent~3.12~150100.3.63.1", rls:"openSUSELeap15.6"))) {
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
