# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2019.1220.1");
  script_cve_id("CVE-2019-3781");
  script_tag(name:"creation_date", value:"2021-06-09 14:57:25 +0000 (Wed, 09 Jun 2021)");
  script_version("2024-02-02T14:37:50+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:50 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-03-08 15:28:58 +0000 (Fri, 08 Mar 2019)");

  script_name("SUSE: Security Advisory (SUSE-SU-2019:1220-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2019:1220-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2019/suse-su-20191220-1/");
  script_xref(name:"URL", value:"https://www.pivotaltracker.com/story/show/130060949");
  script_xref(name:"URL", value:"https://www.pivotaltracker.com/story/show/163156064");
  script_xref(name:"URL", value:"https://www.pivotaltracker.com/story/show/151841382");
  script_xref(name:"URL", value:"https://www.pivotaltracker.com/story/show/150111078");
  script_xref(name:"URL", value:"https://www.pivotaltracker.com/story/show/162745359");
  script_xref(name:"URL", value:"https://www.pivotaltracker.com/story/show/161632713");
  script_xref(name:"URL", value:"https://www.pivotaltracker.com/story/show/162699756");
  script_xref(name:"URL", value:"https://www.pivotaltracker.com/story/show/162747373");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'cf-cli' package(s) announced via the SUSE-SU-2019:1220-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for cf-cli fixes the following issues:

cf-cli was updated: to version 6.43.0 (bsc#1132242)

Enhancements :
`cf curl` supports a new `--fail` flag (primarily for scripting
 purposes) which returns exit code `22` for server errors
 [story]([link moved to references])

Improves `cf delete-orphaned-routes` such that it uses a different
 endpoint, reducing the chance of a race condition when two users are
 simultaneously deleting orphaned routes and associating routes with
 applications [story]([link moved to references])

we've improved the speed of cf services - it now hits a single endpoint
 instead of making individual API calls

Security:
CVE-2019-3781: CF CLI does not sanitize userAC/AEURA(tm)s password in
 verbose/trace/debug.

Fixes issue with running cf login in verbose mode whereby passwords
 which contains regex were not completely redacted

Fixes issue whilst running commands in verbose mode refresh tokens were
 not completely redacted

Other Bug Fixes:
Updates help text for cf curlstory

Now refresh tokens work properly whilst using cf curl with V3 CC API
 endpoints story

Fixes performance degradation for cf services story

cf delete-service requires that you are targeting a space story

cf enable-service access for a service in an org will succeed if you
 have already enabled access for that service in that org story

cf-cli was updated to version 6.42.0:

Minor Enhancements:
updated `cf restage` help text and the first line in the command's
 output to indicate that using this command will cause app downtime
 [story]([link moved to references])

updated the `cf bind-route-service` help text to clarify usage
 instructions [story]([link moved to references])

improved an error message for `cf create-service-boker` to be more
 helpful when the CC API returns a `502` due to an invalid service broker
 catalog

upgraded to Golang 1.11.4
 [story]([link moved to references])

added a short name `ue` for `cf unset-env`
 [story]([link moved to references])

updated `cf marketplace` command to include a new `broker` column to
 prepare for a upcoming services-related feature which will allow
 services to have the same name as long as they are associated with
 different service brokers
 [story]([link moved to references])

Bugs:
fix for `cf enable-service-access -p plan` whereby when we refactored
 the code in CLI `v6.41.0` it created service plan visibilities as part
 of a subsequent run of the command (the unrefactored code skipped
 creating the service plan visibilities), now the command will skip
 creating service plan visibilities as it did prior to the refactor
 [story]([link moved to references])

updated the `cf rename-buildpack` help text which was missing ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'cf-cli' package(s) on SUSE Linux Enterprise Module for CAP 15.");

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

if(release == "SLES15.0") {

  if(!isnull(res = isrpmvuln(pkg:"cf-cli", rpm:"cf-cli~6.43.0~3.3.2", rls:"SLES15.0"))) {
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
