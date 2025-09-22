# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2010-June/016724.html");
  script_oid("1.3.6.1.4.1.25623.1.0.880631");
  script_version("2023-07-12T05:05:04+0000");
  script_tag(name:"last_modification", value:"2023-07-12 05:05:04 +0000 (Wed, 12 Jul 2023)");
  script_tag(name:"creation_date", value:"2011-08-09 08:20:34 +0200 (Tue, 09 Aug 2011)");
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:C/I:C/A:C");
  script_xref(name:"CESA", value:"2010:0458");
  script_cve_id("CVE-2008-5302", "CVE-2008-5303", "CVE-2010-1168", "CVE-2010-1447", "CVE-2005-0448", "CVE-2004-0452");
  script_name("CentOS Update for perl CESA-2010:0458 centos5 i386");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'perl'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS5");
  script_tag(name:"affected", value:"perl on CentOS 5");
  script_tag(name:"insight", value:"Perl is a high-level programming language commonly used for system
  administration utilities and web programming. The Safe extension module
  allows users to compile and execute Perl code in restricted compartments.
  The File::Path module allows users to create and remove directory trees.

  The Safe module did not properly restrict the code of implicitly called
  methods (such as DESTROY and AUTOLOAD) on implicitly blessed objects
  returned as a result of unsafe code evaluation. These methods could have
  been executed unrestricted by Safe when such objects were accessed or
  destroyed. A specially-crafted Perl script executed inside of a Safe
  compartment could use this flaw to bypass intended Safe module
  restrictions. (CVE-2010-1168)

  The Safe module did not properly restrict code compiled in a Safe
  compartment and executed out of the compartment via a subroutine reference
  returned as a result of unsafe code evaluation. A specially-crafted Perl
  script executed inside of a Safe compartment could use this flaw to bypass
  intended Safe module restrictions, if the returned subroutine reference was
  called from outside of the compartment. (CVE-2010-1447)

  Multiple race conditions were found in the way the File::Path module's
  rmtree function removed directory trees. A malicious, local user with write
  access to a directory being removed by a victim, running a Perl script
  using rmtree, could cause the permissions of arbitrary files to be changed
  to world-writable and setuid, or delete arbitrary files via a symbolic link
  attack, if the victim had the privileges to change the permissions of the
  target files or to remove them. (CVE-2008-5302, CVE-2008-5303)

  Red Hat would like to thank Tim Bunce for responsibly reporting the
  CVE-2010-1168 and CVE-2010-1447 issues. Upstream acknowledges Nick Cleaton
  as the original reporter of CVE-2010-1168, and Tim Bunce and Rafal
  Garcia-Suarez as the original reporters of CVE-2010-1447.

  These packages upgrade the Safe extension module to version 2.27. Refer to
  the Safe module's Changes file, linked to in the References, for a full
  list of changes.

  Users of perl are advised to upgrade to these updated packages, which
  correct these issues. All applications using the Safe or File::Path modules
  must be restarted for this update to take effect.");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";

if(release == "CentOS5")
{

  if ((res = isrpmvuln(pkg:"perl", rpm:"perl~5.8.8~32.el5_5.1", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"perl-suidperl", rpm:"perl-suidperl~5.8.8~32.el5_5.1", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
