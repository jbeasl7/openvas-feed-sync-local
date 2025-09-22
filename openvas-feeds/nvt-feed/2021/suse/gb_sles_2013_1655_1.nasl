# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2013.1655.1");
  script_cve_id("CVE-2012-5519");
  script_tag(name:"creation_date", value:"2021-06-09 14:58:23 +0000 (Wed, 09 Jun 2021)");
  script_version("2024-02-02T05:06:07+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:07 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_name("SUSE: Security Advisory (SUSE-SU-2013:1655-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP2|SLES11\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2013:1655-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2013/suse-su-20131655-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'CUPS' package(s) announced via the SUSE-SU-2013:1655-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The following security issue has been fixed in the CUPS print daemon CVE-2012-5519:

The patch adds better default protection against misuse of privileges by normal users who have been specifically allowed by root to do cupsd configuration changes

The new ConfigurationChangeRestriction cupsd.conf directive specifies the level of restriction for cupsd.conf changes that happen via HTTP/IPP requests to the running cupsd
(e.g. via CUPS web interface or via the cupsctl command).

By default certain cupsd.conf directives that deal with filenames, paths, and users can no longer be changed via requests to the running cupsd but only by manual editing the cupsd.conf file and its default file permissions permit only root to write the cupsd.conf file.

Those directives are: ConfigurationChangeRestriction,
AccessLog, BrowseLDAPCACertFile, CacheDir, ConfigFilePerm,
DataDir, DocumentRoot, ErrorLog, FileDevice, FontPath,
Group, LogFilePerm, PageLog, Printcap, PrintcapFormat,
PrintcapGUI, RemoteRoot, RequestRoot, ServerBin,
ServerCertificate, ServerKey, ServerRoot, StateDir,
SystemGroup, SystemGroupAuthKey, TempDir, User.

The default group of users who are allowed to do cupsd configuration changes via requests to the running cupsd
(i.e. the SystemGroup directive in cupsd.conf) is set to
'root' only.

Additionally the following bug has been fixed:

 * strip trailing '@REALM' from username for Kerberos authentication (CUPS STR#3972 bnc#827109)

Security Issue reference:

 * CVE-2012-5519
>");

  script_tag(name:"affected", value:"'CUPS' package(s) on SUSE Linux Enterprise Desktop 11-SP2, SUSE Linux Enterprise Desktop 11-SP3, SUSE Linux Enterprise Server 11-SP2, SUSE Linux Enterprise Server 11-SP3, SUSE Linux Enterprise Software Development Kit 11-SP2, SUSE Linux Enterprise Software Development Kit 11-SP3.");

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

if(release == "SLES11.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"cups", rpm:"cups~1.3.9~8.46.48.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cups-client", rpm:"cups-client~1.3.9~8.46.48.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cups-libs", rpm:"cups-libs~1.3.9~8.46.48.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cups-libs-32bit", rpm:"cups-libs-32bit~1.3.9~8.46.48.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cups-libs-x86", rpm:"cups-libs-x86~1.3.9~8.46.48.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES11.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"cups", rpm:"cups~1.3.9~8.46.48.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cups-client", rpm:"cups-client~1.3.9~8.46.48.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cups-libs", rpm:"cups-libs~1.3.9~8.46.48.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cups-libs-32bit", rpm:"cups-libs-32bit~1.3.9~8.46.48.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cups-libs-x86", rpm:"cups-libs-x86~1.3.9~8.46.48.1", rls:"SLES11.0SP3"))) {
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
