from net.grinder.script.Grinder import grinder
from net.grinder.script import Test

from java.util import Random

from java.sql import DriverManager
from com.mysql.jdbc import Driver

DriverManager.registerDriver(Driver())

p = grinder.getProperties()

p.setLong("grinder.threads", 8)
p.setLong("grinder.runs", 100000000)
p.setLong("grinder.duration", 120 * 1000)

t = Test(1, "Query")

def getConnection():
    return DriverManager.getConnection(
        "jdbc:mysql://server/geoip", "geoip", "geoip")

class TestRunner:
  def __init__(self):
    self.connection = getConnection()

  def __call__(self):
    r = Random()
    s = self.connection.createStatement()

    q = t.wrap(s)

    ip = "%i.%i.%i.%i" % ((r.nextInt() % 256), (r.nextInt() % 256), (r.nextInt() % 256), (r.nextInt() % 256))

    # Using BETWEEN
    #q.execute("select country_code from ip_country_bad where inet_aton('%s') between ip_from and ip_to" % ip )

    # Using MBRCONTAINS
    #q.execute("select country_code from ip_country where mbrcontains(ip_poly, pointfromwkb(point(inet_aton('%s'), 0)))" % ip )

    s.close()

  def __del__(self):
    self.connection.close()
