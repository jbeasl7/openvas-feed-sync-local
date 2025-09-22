# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856635");
  script_cve_id("CVE-2023-6917", "CVE-2024-45769", "CVE-2024-45770");
  script_tag(name:"creation_date", value:"2024-10-31 05:01:00 +0000 (Thu, 31 Oct 2024)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:M/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-04-01 15:34:51 +0000 (Tue, 01 Apr 2025)");

  script_name("openSUSE Security Advisory (SUSE-SU-2024:3785-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.5");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:3785-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2024/suse-su-20243785-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1217826");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222815");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1230551");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1230552");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231345");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2024-October/019697.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'pcp' package(s) announced via the SUSE-SU-2024:3785-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for pcp fixes the following issues:

pcp was updated from version 5.2.5 to version 6.2.0 (jsc#PED-8192, jsc#PED-8389):

- Security issues fixed:

 * CVE-2024-45770: Fixed a symlink attack that allows escalating from the pcp to the root user (bsc#1230552)
 * CVE-2024-45769: Fixed a heap corruption through metric pmstore operations (bsc#1230551)
 * CVE-2023-6917: Fixed local privilege escalation from pcp user to root in /usr/libexec/pcp/lib/pmproxy (bsc#1217826)

- Major changes:

 * Add version 3 PCP archive support: instance domain change-deltas,
 Y2038-safe timestamps, nanosecond-precision timestamps, arbitrary timezones support, 64-bit file offsets used
 throughout for larger (beyond 2GB) individual volumes
 + Opt-in using the /etc/pcp.conf PCP_ARCHIVE_VERSION setting
 + Version 2 archives remain the default (for next few years)
 * Switch to using OpenSSL only throughout PCP (dropped NSS/NSPR),
 this impacts on libpcp, PMAPI clients and PMCD use of encryption,
 these are now configured and used consistently with pmproxy HTTPS support and redis-server, which were both already
 using OpenSSL.
 * New nanosecond precision timestamp PMAPI calls for PCP library interfaces that make use of timestamps
 These are all optional, and full backward compatibility is preserved for existing tools.
 * For the full list of changes please consult the packaged CHANGELOG file

- Other packaging changes:

 * Moved pmlogger_daily into the main package (bsc#1222815)
 * Change dependency from openssl-devel >= 1.1.1 to openssl-devel >= 1.0.2p.
 Required for SLE-12
 * Introduce 'pmda-resctrl' package, disabled for architectures other than x86_64
 * Change the architecture for various subpackages to 'noarch' as they contain no binaries
 * Disable 'pmda-mssql', as it fails to build");

  script_tag(name:"affected", value:"'pcp' package(s) on openSUSE Leap 15.5.");

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

if(release == "openSUSELeap15.5") {

  if(!isnull(res = isrpmvuln(pkg:"libpcp-devel", rpm:"libpcp-devel~6.2.0~150500.8.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcp3", rpm:"libpcp3~6.2.0~150500.8.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcp_gui2", rpm:"libpcp_gui2~6.2.0~150500.8.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcp_import1", rpm:"libpcp_import1~6.2.0~150500.8.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcp_mmv1", rpm:"libpcp_mmv1~6.2.0~150500.8.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcp_trace2", rpm:"libpcp_trace2~6.2.0~150500.8.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcp_web1", rpm:"libpcp_web1~6.2.0~150500.8.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcp", rpm:"pcp~6.2.0~150500.8.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcp-conf", rpm:"pcp-conf~6.2.0~150500.8.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcp-devel", rpm:"pcp-devel~6.2.0~150500.8.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcp-doc", rpm:"pcp-doc~6.2.0~150500.8.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcp-export-pcp2elasticsearch", rpm:"pcp-export-pcp2elasticsearch~6.2.0~150500.8.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcp-export-pcp2graphite", rpm:"pcp-export-pcp2graphite~6.2.0~150500.8.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcp-export-pcp2influxdb", rpm:"pcp-export-pcp2influxdb~6.2.0~150500.8.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcp-export-pcp2json", rpm:"pcp-export-pcp2json~6.2.0~150500.8.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcp-export-pcp2spark", rpm:"pcp-export-pcp2spark~6.2.0~150500.8.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcp-export-pcp2xml", rpm:"pcp-export-pcp2xml~6.2.0~150500.8.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcp-export-pcp2zabbix", rpm:"pcp-export-pcp2zabbix~6.2.0~150500.8.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcp-gui", rpm:"pcp-gui~6.2.0~150500.8.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcp-import-collectl2pcp", rpm:"pcp-import-collectl2pcp~6.2.0~150500.8.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcp-import-ganglia2pcp", rpm:"pcp-import-ganglia2pcp~6.2.0~150500.8.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcp-import-iostat2pcp", rpm:"pcp-import-iostat2pcp~6.2.0~150500.8.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcp-import-mrtg2pcp", rpm:"pcp-import-mrtg2pcp~6.2.0~150500.8.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcp-import-sar2pcp", rpm:"pcp-import-sar2pcp~6.2.0~150500.8.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcp-pmda-activemq", rpm:"pcp-pmda-activemq~6.2.0~150500.8.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcp-pmda-apache", rpm:"pcp-pmda-apache~6.2.0~150500.8.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcp-pmda-bash", rpm:"pcp-pmda-bash~6.2.0~150500.8.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcp-pmda-bonding", rpm:"pcp-pmda-bonding~6.2.0~150500.8.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcp-pmda-cifs", rpm:"pcp-pmda-cifs~6.2.0~150500.8.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcp-pmda-cisco", rpm:"pcp-pmda-cisco~6.2.0~150500.8.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcp-pmda-dbping", rpm:"pcp-pmda-dbping~6.2.0~150500.8.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcp-pmda-dm", rpm:"pcp-pmda-dm~6.2.0~150500.8.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcp-pmda-docker", rpm:"pcp-pmda-docker~6.2.0~150500.8.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcp-pmda-ds389", rpm:"pcp-pmda-ds389~6.2.0~150500.8.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcp-pmda-ds389log", rpm:"pcp-pmda-ds389log~6.2.0~150500.8.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcp-pmda-elasticsearch", rpm:"pcp-pmda-elasticsearch~6.2.0~150500.8.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcp-pmda-gfs2", rpm:"pcp-pmda-gfs2~6.2.0~150500.8.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcp-pmda-gluster", rpm:"pcp-pmda-gluster~6.2.0~150500.8.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcp-pmda-gpfs", rpm:"pcp-pmda-gpfs~6.2.0~150500.8.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcp-pmda-gpsd", rpm:"pcp-pmda-gpsd~6.2.0~150500.8.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcp-pmda-hacluster", rpm:"pcp-pmda-hacluster~6.2.0~150500.8.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcp-pmda-haproxy", rpm:"pcp-pmda-haproxy~6.2.0~150500.8.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcp-pmda-infiniband", rpm:"pcp-pmda-infiniband~6.2.0~150500.8.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcp-pmda-json", rpm:"pcp-pmda-json~6.2.0~150500.8.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcp-pmda-lmsensors", rpm:"pcp-pmda-lmsensors~6.2.0~150500.8.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcp-pmda-logger", rpm:"pcp-pmda-logger~6.2.0~150500.8.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcp-pmda-lustre", rpm:"pcp-pmda-lustre~6.2.0~150500.8.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcp-pmda-lustrecomm", rpm:"pcp-pmda-lustrecomm~6.2.0~150500.8.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcp-pmda-mailq", rpm:"pcp-pmda-mailq~6.2.0~150500.8.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcp-pmda-memcache", rpm:"pcp-pmda-memcache~6.2.0~150500.8.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcp-pmda-mic", rpm:"pcp-pmda-mic~6.2.0~150500.8.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcp-pmda-mounts", rpm:"pcp-pmda-mounts~6.2.0~150500.8.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcp-pmda-mysql", rpm:"pcp-pmda-mysql~6.2.0~150500.8.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcp-pmda-named", rpm:"pcp-pmda-named~6.2.0~150500.8.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcp-pmda-netcheck", rpm:"pcp-pmda-netcheck~6.2.0~150500.8.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcp-pmda-netfilter", rpm:"pcp-pmda-netfilter~6.2.0~150500.8.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcp-pmda-news", rpm:"pcp-pmda-news~6.2.0~150500.8.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcp-pmda-nfsclient", rpm:"pcp-pmda-nfsclient~6.2.0~150500.8.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcp-pmda-nginx", rpm:"pcp-pmda-nginx~6.2.0~150500.8.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcp-pmda-nutcracker", rpm:"pcp-pmda-nutcracker~6.2.0~150500.8.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcp-pmda-nvidia-gpu", rpm:"pcp-pmda-nvidia-gpu~6.2.0~150500.8.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcp-pmda-openmetrics", rpm:"pcp-pmda-openmetrics~6.2.0~150500.8.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcp-pmda-openvswitch", rpm:"pcp-pmda-openvswitch~6.2.0~150500.8.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcp-pmda-oracle", rpm:"pcp-pmda-oracle~6.2.0~150500.8.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcp-pmda-pdns", rpm:"pcp-pmda-pdns~6.2.0~150500.8.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcp-pmda-perfevent", rpm:"pcp-pmda-perfevent~6.2.0~150500.8.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcp-pmda-postfix", rpm:"pcp-pmda-postfix~6.2.0~150500.8.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcp-pmda-rabbitmq", rpm:"pcp-pmda-rabbitmq~6.2.0~150500.8.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcp-pmda-redis", rpm:"pcp-pmda-redis~6.2.0~150500.8.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcp-pmda-roomtemp", rpm:"pcp-pmda-roomtemp~6.2.0~150500.8.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcp-pmda-rsyslog", rpm:"pcp-pmda-rsyslog~6.2.0~150500.8.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcp-pmda-samba", rpm:"pcp-pmda-samba~6.2.0~150500.8.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcp-pmda-sendmail", rpm:"pcp-pmda-sendmail~6.2.0~150500.8.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcp-pmda-shping", rpm:"pcp-pmda-shping~6.2.0~150500.8.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcp-pmda-slurm", rpm:"pcp-pmda-slurm~6.2.0~150500.8.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcp-pmda-smart", rpm:"pcp-pmda-smart~6.2.0~150500.8.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcp-pmda-snmp", rpm:"pcp-pmda-snmp~6.2.0~150500.8.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcp-pmda-sockets", rpm:"pcp-pmda-sockets~6.2.0~150500.8.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcp-pmda-summary", rpm:"pcp-pmda-summary~6.2.0~150500.8.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcp-pmda-systemd", rpm:"pcp-pmda-systemd~6.2.0~150500.8.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcp-pmda-trace", rpm:"pcp-pmda-trace~6.2.0~150500.8.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcp-pmda-unbound", rpm:"pcp-pmda-unbound~6.2.0~150500.8.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcp-pmda-weblog", rpm:"pcp-pmda-weblog~6.2.0~150500.8.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcp-pmda-zimbra", rpm:"pcp-pmda-zimbra~6.2.0~150500.8.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcp-pmda-zswap", rpm:"pcp-pmda-zswap~6.2.0~150500.8.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcp-system-tools", rpm:"pcp-system-tools~6.2.0~150500.8.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcp-testsuite", rpm:"pcp-testsuite~6.2.0~150500.8.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcp-zeroconf", rpm:"pcp-zeroconf~6.2.0~150500.8.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-PCP-LogImport", rpm:"perl-PCP-LogImport~6.2.0~150500.8.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-PCP-LogSummary", rpm:"perl-PCP-LogSummary~6.2.0~150500.8.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-PCP-MMV", rpm:"perl-PCP-MMV~6.2.0~150500.8.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-PCP-PMDA", rpm:"perl-PCP-PMDA~6.2.0~150500.8.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-pcp", rpm:"python3-pcp~6.2.0~150500.8.6.1", rls:"openSUSELeap15.5"))) {
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
