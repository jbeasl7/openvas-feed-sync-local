# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_xref(name:"URL", value:"http://lists.mandriva.com/security-announce/2011-03/msg00000.php");
  script_oid("1.3.6.1.4.1.25623.1.0.831343");
  script_version("2023-11-02T05:05:26+0000");
  script_tag(name:"last_modification", value:"2023-11-02 05:05:26 +0000 (Thu, 02 Nov 2023)");
  script_tag(name:"creation_date", value:"2011-03-07 06:45:55 +0100 (Mon, 07 Mar 2011)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-04 14:05:00 +0000 (Tue, 04 Aug 2020)");
  script_xref(name:"MDVSA", value:"2011:039");
  script_cve_id("CVE-2010-1665", "CVE-2010-1664", "CVE-2010-3248", "CVE-2010-1784", "CVE-2010-1785", "CVE-2010-1786", "CVE-2010-1787", "CVE-2010-1780", "CVE-2010-1781", "CVE-2010-1782", "CVE-2010-1783", "CVE-2010-1788", "CVE-2010-1386", "CVE-2010-1387", "CVE-2010-1389", "CVE-2010-3259", "CVE-2010-1771", "CVE-2010-1770", "CVE-2010-1773", "CVE-2010-1772", "CVE-2010-1774", "CVE-2010-2264", "CVE-2010-0054", "CVE-2010-0053", "CVE-2010-0052", "CVE-2010-0051", "CVE-2010-0050", "CVE-2010-1762", "CVE-2010-1760", "CVE-2010-1761", "CVE-2010-1766", "CVE-2010-1767", "CVE-2010-1764", "CVE-2010-0048", "CVE-2010-0049", "CVE-2010-2647", "CVE-2010-2648", "CVE-2010-0046", "CVE-2010-0047", "CVE-2010-1759", "CVE-2010-1758", "CVE-2009-2841", "CVE-2010-4040", "CVE-2010-1421", "CVE-2010-1422", "CVE-2010-0656", "CVE-2010-0651", "CVE-2010-0650", "CVE-2010-4198", "CVE-2010-4197", "CVE-2010-3812", "CVE-2010-3813", "CVE-2010-3113", "CVE-2010-3116", "CVE-2010-3115", "CVE-2010-3114", "CVE-2010-0647", "CVE-2010-3119", "CVE-2010-0314", "CVE-2010-4206", "CVE-2010-4204", "CVE-2009-2797", "CVE-2010-1407", "CVE-2010-1406", "CVE-2010-1405", "CVE-2010-1404", "CVE-2010-1403", "CVE-2010-1402", "CVE-2010-1401", "CVE-2010-1400", "CVE-2010-1409", "CVE-2010-1408", "CVE-2010-1807", "CVE-2010-3255", "CVE-2010-1410", "CVE-2010-1412", "CVE-2010-3257", "CVE-2010-1414", "CVE-2010-1415", "CVE-2010-1416", "CVE-2010-1417", "CVE-2010-1418", "CVE-2010-1419", "CVE-2010-1814", "CVE-2010-1815", "CVE-2010-1812", "CVE-2010-1793", "CVE-2010-1792", "CVE-2010-1791", "CVE-2010-1790", "CVE-2010-1397", "CVE-2010-1396", "CVE-2010-1395", "CVE-2010-1394", "CVE-2010-1393", "CVE-2010-1392", "CVE-2010-1391", "CVE-2010-1390", "CVE-2010-1398");
  script_name("Mandriva Update for webkit MDVSA-2011:039 (webkit)");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'webkit'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Mandrake Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mandriva_mandrake_linux", "ssh/login/release", re:"ssh/login/release=MNDK_2010\.1");
  script_tag(name:"affected", value:"webkit on Mandriva Linux 2010.1,
  Mandriva Linux 2010.1/X86_64");
  script_tag(name:"insight", value:"Multiple cross-site scripting, denial of service and arbitrary code
  execution security flaws were discovered in webkit.

  Please consult the CVE web links for further information.

  The updated packages have been upgraded to the latest version (1.2.7)
  to correct these issues.");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "MNDK_2010.1")
{

  if ((res = isrpmvuln(pkg:"libwebkitgtk1.0_2", rpm:"libwebkitgtk1.0_2~1.2.7~0.1mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libwebkitgtk1.0-devel", rpm:"libwebkitgtk1.0-devel~1.2.7~0.1mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"webkit1.0", rpm:"webkit1.0~1.2.7~0.1mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"webkit1.0-webinspector", rpm:"webkit1.0-webinspector~1.2.7~0.1mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"webkit", rpm:"webkit~1.2.7~0.1mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"webkit-gtklauncher", rpm:"webkit-gtklauncher~1.2.7~0.1mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"webkit-jsc", rpm:"webkit-jsc~1.2.7~0.1mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64webkitgtk1.0_2", rpm:"lib64webkitgtk1.0_2~1.2.7~0.1mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64webkitgtk1.0-devel", rpm:"lib64webkitgtk1.0-devel~1.2.7~0.1mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
