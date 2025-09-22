# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2020.3147.1");
  script_cve_id("CVE-2019-16770", "CVE-2019-5418", "CVE-2019-5419", "CVE-2019-5420", "CVE-2020-11076", "CVE-2020-11077", "CVE-2020-15169", "CVE-2020-5247", "CVE-2020-5249", "CVE-2020-5267", "CVE-2020-8164", "CVE-2020-8165", "CVE-2020-8166", "CVE-2020-8167", "CVE-2020-8184", "CVE-2020-8185");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-06-24 17:33:34 +0000 (Wed, 24 Jun 2020)");

  script_name("SUSE: Security Advisory (SUSE-SU-2020:3147-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2020:3147-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2020/suse-su-20203147-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1172177");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1172182");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1172184");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1172186");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1173351");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2020-November/007691.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'rmt-server' package(s) announced via the SUSE-SU-2020:3147-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for rmt-server fixes the following issues:

- Version 2.6.5
- Solved potential bug of SCC repository URLs changing over time. RMT
 now self heals by removing the previous invalid repository and
 creating the correct one.

- Version 2.6.4
- Add web server settings to /etc/rmt.conf:
 Now it's possible to configure the minimum and maximum threads count as well
 the number of web server workers to be booted through /etc/rmt.conf.

- Version 2.6.3
- Instead of using an MD5 of URLs for custom repository friendly_ids,
 RMT now builds an ID from the name.

- Version 2.6.2
- Fix RMT file caching based on timestamps:
 Previously, RMT sent GET requests with the header 'If-Modified-Since' to a
 repository server and if the response had a 304 (Not Modified), it would copy
 a file from the local cache instead of downloading. However, if the local file
 timestamp accidentally changed to a date newer than the one on the repository
 server, RMT would have an outdated file, which caused some errors.
 Now, RMT makes HEAD requests to the repositories servers and inspect the
 'Last-Modified' header to decide whether to download a file or copy it from
 cache, by comparing the equalness of timestamps.


- Version 2.6.1
- Fixed an issue where relative paths supplied to `rmt-cli import repos`
 caused the command to fail.

- Version 2.6.0
- Friendlier IDs for custom repositories:
 In an effort to simplify the handling of SCC and custom repositories,
 RMT now has friendly IDs. For SCC repositories, it's the same SCC ID
 as before. For custom repositories, it can either be user provided
 or RMT generated (MD5 of the provided URL).
 Benefits:
 * `rmt-cli mirror repositories` now works for custom repositories.
 * Custom repository IDs can be the same across RMT instances.
 * No more confusing 'SCC ID' vs 'ID' in `rmt-cli` output.
 Deprecation Warnings:
 * RMT now uses a different ID for custom repositories than before.
 RMT still supports that old ID, but it's recommended to start
 using the new ID to ensure future compatibility.

- Version 2.5.20
- Updated rails from 6.0.3.2 to 6.0.3.3:
 - actionview (CVE-2020-15169)

- Version 2.5.19
- RMT now has the ability to remove local systems with the command
 `rmt-cli systems remove`.

- Version 2.5.18
- Fixed exit code for `rmt-cli mirror` and its subcommands. Now it exits with 1
 whenever an error occurs during mirroring
- Improved message logging for `rtm-cli mirror`. Instead of logging an error
 when it occurs, the command summarize all errors at the end of execution. Now
 log messages have colors to better identify failure/success.

- Version 2.5.17
- RMT no longer provides the installer updates repository to systems via its
 zypper service. This repository is used during the installation process, as
 it provides an up-to-date installation experience, but it has no use on an
 already installed system.

- Version 2.5.16
- Updated RMT's ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'rmt-server' package(s) on SUSE Linux Enterprise Server 15, SUSE Linux Enterprise Server for SAP Applications 15.");

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

if(release == "SLES15.0") {

  if(!isnull(res = isrpmvuln(pkg:"rmt-server", rpm:"rmt-server~2.6.5~3.34.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rmt-server-config", rpm:"rmt-server-config~2.6.5~3.34.1", rls:"SLES15.0"))) {
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
