# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2011-March/msg00047.html");
  script_oid("1.3.6.1.4.1.25623.1.0.870608");
  script_version("2024-03-21T05:06:54+0000");
  script_tag(name:"last_modification", value:"2024-03-21 05:06:54 +0000 (Thu, 21 Mar 2024)");
  script_tag(name:"creation_date", value:"2012-06-06 10:33:48 +0530 (Wed, 06 Jun 2012)");
  script_cve_id("CVE-2011-1098", "CVE-2011-1154", "CVE-2011-1155");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_xref(name:"RHSA", value:"2011:0407-01");
  script_name("RedHat Update for logrotate RHSA-2011:0407-01");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'logrotate'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_6");
  script_tag(name:"affected", value:"logrotate on Red Hat Enterprise Linux Desktop (v. 6),
  Red Hat Enterprise Linux Server (v. 6),
  Red Hat Enterprise Linux Workstation (v. 6)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"insight", value:"The logrotate utility simplifies the administration of multiple log files,
  allowing the automatic rotation, compression, removal, and mailing of log
  files.

  A shell command injection flaw was found in the way logrotate handled the
  shred directive. A specially-crafted log file could cause logrotate to
  execute arbitrary commands with the privileges of the user running
  logrotate (root, by default). Note: The shred directive is not enabled by
  default. (CVE-2011-1154)

  A race condition flaw was found in the way logrotate applied permissions
  when creating new log files. In some specific configurations, a local
  attacker could use this flaw to open new log files before logrotate applies
  the final permissions, possibly leading to the disclosure of sensitive
  information. (CVE-2011-1098)

  An input sanitization flaw was found in logrotate. A log file with a
  specially-crafted file name could cause logrotate to abort when attempting
  to process that file a subsequent time. (CVE-2011-1155)

  All logrotate users should upgrade to this updated package, which contains
  backported patches to resolve these issues.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "RHENT_6")
{

  if ((res = isrpmvuln(pkg:"logrotate", rpm:"logrotate~3.7.8~12.el6_0.1", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"logrotate-debuginfo", rpm:"logrotate-debuginfo~3.7.8~12.el6_0.1", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
