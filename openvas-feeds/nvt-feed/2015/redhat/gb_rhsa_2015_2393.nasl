# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.871496");
  script_version("2024-03-21T05:06:54+0000");
  script_tag(name:"last_modification", value:"2024-03-21 05:06:54 +0000 (Thu, 21 Mar 2024)");
  script_tag(name:"creation_date", value:"2015-11-20 06:23:13 +0100 (Fri, 20 Nov 2015)");
  script_cve_id("CVE-2014-8710", "CVE-2014-8711", "CVE-2014-8712", "CVE-2014-8713",
                "CVE-2014-8714", "CVE-2015-0562", "CVE-2015-0563", "CVE-2015-0564",
                "CVE-2015-2188", "CVE-2015-2189", "CVE-2015-2191", "CVE-2015-3182",
                "CVE-2015-3810", "CVE-2015-3811", "CVE-2015-3812", "CVE-2015-3813",
                "CVE-2015-6243", "CVE-2015-6244", "CVE-2015-6245", "CVE-2015-6246",
                "CVE-2015-6248");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-12-27 16:08:00 +0000 (Fri, 27 Dec 2019)");
  script_tag(name:"qod_type", value:"package");
  script_name("RedHat Update for wireshark RHSA-2015:2393-01");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'wireshark'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The wireshark packages contain a network
protocol analyzer used to capture and browse the traffic running on a computer
network.

Several denial of service flaws were found in Wireshark. Wireshark could
crash or stop responding if it read a malformed packet off a network, or
opened a malicious dump file. (CVE-2015-2188, CVE-2015-2189, CVE-2015-2191,
CVE-2015-3810, CVE-2015-3811, CVE-2015-3812, CVE-2015-3813, CVE-2014-8710,
CVE-2014-8711, CVE-2014-8712, CVE-2014-8713, CVE-2014-8714, CVE-2015-0562,
CVE-2015-0563, CVE-2015-0564, CVE-2015-3182, CVE-2015-6243, CVE-2015-6244,
CVE-2015-6245, CVE-2015-6246, CVE-2015-6248)

The CVE-2015-3182 issue was discovered by Martin ember of Red Hat.

The wireshark packages have been upgraded to upstream version 1.10.14,
which provides a number of bug fixes and enhancements over the previous
version. (BZ#1238676)

This update also fixes the following bug:

  * Prior to this update, when using the tshark utility to capture packets
over the interface, tshark failed to create output files in the .pcap
format even if it was specified using the '-F' option. This bug has been
fixed, the '-F' option is now honored, and the result saved in the .pcap
format as expected. (BZ#1227199)

In addition, this update adds the following enhancement:

  * Previously, wireshark included only microseconds in the .pcapng format.
With this update, wireshark supports nanosecond time stamp precision to
allow for more accurate time stamps. (BZ#1213339)

All wireshark users are advised to upgrade to these updated packages, which
correct these issues and add these enhancements. All running instances of
Wireshark must be restarted for the update to take effect.");
  script_tag(name:"affected", value:"wireshark on Red Hat Enterprise Linux Server (v. 7)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_xref(name:"RHSA", value:"2015:2393-01");
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2015-November/msg00045.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_7");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "RHENT_7")
{

  if ((res = isrpmvuln(pkg:"wireshark", rpm:"wireshark~1.10.14~7.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"wireshark-debuginfo", rpm:"wireshark-debuginfo~1.10.14~7.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"wireshark-gnome", rpm:"wireshark-gnome~1.10.14~7.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
